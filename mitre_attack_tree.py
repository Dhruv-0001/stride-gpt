"""
Enhanced Attack Tree Generation with MITRE ATT&CK Integration

This module extends the basic attack tree functionality to include:
1. MITRE ATT&CK technique integration
2. Real-world attack group references
3. Enhanced visualizations with citations
4. Professional reporting capabilities
"""

import json
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Optional, Tuple, Any
import streamlit as st
from datetime import datetime

from mitre_attack import MITREAttackData, STRIDEMITREMapper


class MITREEnhancedAttackTree:
    """Enhanced attack tree with MITRE ATT&CK integration"""
    
    def __init__(self, mitre_data: MITREAttackData):
        self.mitre_data = mitre_data
        self.mapper = STRIDEMITREMapper(mitre_data)
        self.attack_graph = nx.DiGraph()
        
    def generate_enhanced_attack_tree(self, threat_model: List[Dict], app_type: str = "web_application") -> Dict:
        """
        Generate enhanced attack tree with MITRE techniques
        
        Args:
            threat_model: List of STRIDE threats
            app_type: Application type for context
            
        Returns:
            Dictionary containing attack tree data and visualizations
        """
        
        # Map threats to MITRE techniques
        enhanced_threats = self.mapper.map_stride_to_mitre(threat_model, app_type)
        
        # Build attack tree structure
        attack_tree = self._build_attack_tree_structure(enhanced_threats, app_type)
        
        # Generate visualizations
        mermaid_diagram = self._generate_mermaid_diagram(attack_tree)
        plotly_graph = self._generate_plotly_graph(attack_tree)
        
        # Generate professional report
        report = self._generate_attack_tree_report(attack_tree, enhanced_threats)
        
        return {
            "attack_tree": attack_tree,
            "enhanced_threats": enhanced_threats,
            "mermaid_diagram": mermaid_diagram,
            "plotly_graph": plotly_graph,
            "report": report,
            "mitre_navigator_url": self._generate_navigator_url(enhanced_threats)
        }
    
    def _build_attack_tree_structure(self, enhanced_threats: List[Dict], app_type: str) -> Dict:
        """Build hierarchical attack tree structure"""
        
        # Root node
        root = {
            "id": "root",
            "name": f"Compromise {app_type.replace('_', ' ').title()}",
            "type": "goal",
            "children": [],
            "mitre_techniques": [],
            "likelihood": "High",
            "impact": "High"
        }
        
        # Group threats by STRIDE category
        threat_groups = {}
        for threat in enhanced_threats:
            category = threat["Threat Type"]
            if category not in threat_groups:
                threat_groups[category] = []
            threat_groups[category].append(threat)
        
        # Create intermediate nodes for each STRIDE category
        for category, threats in threat_groups.items():
            category_node = {
                "id": f"stride_{category.lower().replace(' ', '_')}",
                "name": f"{category} Attacks",
                "type": "intermediate",
                "children": [],
                "mitre_techniques": [],
                "description": f"Various {category.lower()} attack vectors"
            }
            
            # Add specific attack vectors for each threat
            for i, threat in enumerate(threats):
                attack_node = {
                    "id": f"{category.lower().replace(' ', '_')}_attack_{i+1}",
                    "name": threat["Scenario"][:50] + "..." if len(threat["Scenario"]) > 50 else threat["Scenario"],
                    "type": "attack_vector",
                    "description": threat["Scenario"],
                    "impact": threat["Potential Impact"],
                    "mitre_techniques": threat.get("mitre_techniques", []),
                    "mitre_tactics": threat.get("mitre_tactics", []),
                    "children": []
                }
                
                # Add technique-specific steps
                if threat.get("mitre_techniques"):
                    for technique in threat["mitre_techniques"]:
                        technique_node = {
                            "id": f"technique_{technique['id'].lower()}",
                            "name": f"{technique['id']}: {technique['name']}",
                            "type": "technique",
                            "description": technique["description"],
                            "mitre_url": technique["url"],
                            "platforms": technique.get("platforms", []),
                            "tactics": technique.get("tactics", []),
                            "children": []
                        }
                        attack_node["children"].append(technique_node)
                
                category_node["children"].append(attack_node)
            
            # Collect all techniques for the category
            all_techniques = []
            for threat in threats:
                all_techniques.extend(threat.get("mitre_techniques", []))
            category_node["mitre_techniques"] = all_techniques
            
            root["children"].append(category_node)
        
        return root
    
    def _generate_mermaid_diagram(self, attack_tree: Dict) -> str:
        """Generate Mermaid diagram for attack tree"""
        
        mermaid_lines = ["graph TD"]
        
        def add_node_recursive(node, parent_id=None):
            node_id = node["id"]
            node_name = node["name"].replace('"', "'")
            
            # Style nodes based on type
            if node["type"] == "goal":
                mermaid_lines.append(f'    {node_id}["{node_name}"]')
                mermaid_lines.append(f'    classDef goal fill:#ff6b6b,stroke:#000,stroke-width:3px')
                mermaid_lines.append(f'    class {node_id} goal')
            elif node["type"] == "intermediate":
                mermaid_lines.append(f'    {node_id}["{node_name}"]')
                mermaid_lines.append(f'    classDef intermediate fill:#4ecdc4,stroke:#000,stroke-width:2px')
                mermaid_lines.append(f'    class {node_id} intermediate')
            elif node["type"] == "attack_vector":
                mermaid_lines.append(f'    {node_id}["{node_name}"]')
                mermaid_lines.append(f'    classDef attack fill:#ffe66d,stroke:#000,stroke-width:2px')
                mermaid_lines.append(f'    class {node_id} attack')
            elif node["type"] == "technique":
                technique_id = node_name.split(":")[0] if ":" in node_name else ""
                mermaid_lines.append(f'    {node_id}["{node_name}"]')
                mermaid_lines.append(f'    click {node_id} "{node.get("mitre_url", "#")}" "Click to view in MITRE ATT&CK"')
                mermaid_lines.append(f'    classDef technique fill:#ff8b94,stroke:#000,stroke-width:1px')
                mermaid_lines.append(f'    class {node_id} technique')
            
            # Add connection to parent
            if parent_id:
                mermaid_lines.append(f'    {parent_id} --> {node_id}')
            
            # Process children
            for child in node.get("children", []):
                add_node_recursive(child, node_id)
        
        add_node_recursive(attack_tree)
        
        return "\n".join(mermaid_lines)
    
    def _generate_plotly_graph(self, attack_tree: Dict) -> go.Figure:
        """Generate interactive Plotly graph for attack tree"""
        
        # Build networkx graph
        G = nx.DiGraph()
        
        def add_to_graph(node, parent_id=None):
            node_id = node["id"]
            node_name = node["name"]
            
            # Add node with attributes
            G.add_node(node_id, 
                      name=node_name,
                      type=node["type"],
                      description=node.get("description", ""),
                      mitre_techniques=len(node.get("mitre_techniques", [])))
            
            # Add edge from parent
            if parent_id:
                G.add_edge(parent_id, node_id)
            
            # Process children
            for child in node.get("children", []):
                add_to_graph(child, node_id)
        
        add_to_graph(attack_tree)
        
        # Calculate layout
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Create traces
        edge_trace = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace.append(
                go.Scatter(x=[x0, x1, None], y=[y0, y1, None],
                          mode='lines',
                          line=dict(width=2, color='#888'),
                          hoverinfo='none',
                          showlegend=False)
            )
        
        # Node trace
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        node_size = []
        
        color_map = {
            "goal": "#ff6b6b",
            "intermediate": "#4ecdc4", 
            "attack_vector": "#ffe66d",
            "technique": "#ff8b94"
        }
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            node_data = G.nodes[node]
            node_text.append(f"{node_data['name']}<br>Type: {node_data['type']}<br>MITRE Techniques: {node_data['mitre_techniques']}")
            node_color.append(color_map.get(node_data['type'], '#888'))
            node_size.append(20 + node_data['mitre_techniques'] * 5)
        
        node_trace = go.Scatter(x=node_x, y=node_y,
                               mode='markers+text',
                               hoverinfo='text',
                               text=[G.nodes[node]['name'] for node in G.nodes()],
                               textposition="middle center",
                               hovertext=node_text,
                               marker=dict(size=node_size,
                                         color=node_color,
                                         line=dict(width=2, color='black')))
        
        # Create figure
        fig = go.Figure(data=[node_trace] + edge_trace,
                       layout=go.Layout(
                           title=dict(
                               text='Enhanced Attack Tree with MITRE ATT&CK Integration',
                               font=dict(size=16)
                           ),
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           annotations=[ dict(
                               text="Node size indicates number of MITRE techniques",
                               showarrow=False,
                               xref="paper", yref="paper",
                               x=0.005, y=-0.002,
                               xanchor="left", yanchor="bottom",
                               font=dict(color="gray", size=12)
                           )],
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                       )
        
        return fig
    
    def _generate_attack_tree_report(self, attack_tree: Dict, enhanced_threats: List[Dict]) -> str:
        """Generate professional attack tree report"""
        
        report_lines = [
            "# Enhanced Attack Tree Analysis Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Framework:** STRIDE + MITRE ATT&CK",
            "",
            "## Executive Summary",
            f"This attack tree analysis identifies {len(enhanced_threats)} distinct threat scenarios ",
            "mapped to real-world attack techniques documented in the MITRE ATT&CK framework.",
            "",
            "## Threat Landscape Overview"
        ]
        
        # Collect statistics
        all_techniques = []
        tactics_count = {}
        
        for threat in enhanced_threats:
            for technique in threat.get("mitre_techniques", []):
                all_techniques.append(technique)
                for tactic in technique.get("tactics", []):
                    tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
        
        unique_techniques = len(set(t["id"] for t in all_techniques))
        
        report_lines.extend([
            f"- **Total Threats Identified:** {len(enhanced_threats)}",
            f"- **Unique MITRE Techniques:** {unique_techniques}",
            f"- **MITRE Tactics Covered:** {len(tactics_count)}",
            "",
            "### MITRE ATT&CK Tactic Coverage",
        ])
        
        for tactic, count in sorted(tactics_count.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"- **{tactic.title()}:** {count} techniques")
        
        report_lines.extend([
            "",
            "## Detailed Threat Analysis"
        ])
        
        # Add detailed analysis for each threat
        for i, threat in enumerate(enhanced_threats, 1):
            report_lines.extend([
                f"### {i}. {threat['Threat Type']}: {threat['Scenario'][:100]}...",
                f"**Impact:** {threat['Potential Impact']}",
                ""
            ])
            
            if threat.get("mitre_techniques"):
                report_lines.append("**Associated MITRE ATT&CK Techniques:**")
                for technique in threat["mitre_techniques"]:
                    report_lines.append(f"- [{technique['id']} - {technique['name']}]({technique['url']})")
                    if technique.get("platforms"):
                        report_lines.append(f"  - *Platforms:* {', '.join(technique['platforms'])}")
                report_lines.append("")
        
        report_lines.extend([
            "## Recommendations",
            "1. **Prioritize High-Impact Threats:** Focus on threats with multiple MITRE techniques",
            "2. **Implement Defense in Depth:** Address each MITRE tactic with appropriate controls",
            "3. **Continuous Monitoring:** Monitor for indicators of the identified techniques",
            "4. **Regular Updates:** Keep threat model updated as application evolves",
            "",
            "## References",
            "- [MITRE ATT&CK Framework](https://attack.mitre.org/)",
            "- [STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)",
            "",
            f"*Report generated by STRIDE-GPT with MITRE ATT&CK integration*"
        ])
        
        return "\n".join(report_lines)
    
    def _generate_navigator_url(self, enhanced_threats: List[Dict]) -> str:
        """Generate MITRE ATT&CK Navigator URL for the attack tree"""
        
        technique_ids = []
        for threat in enhanced_threats:
            for technique in threat.get("mitre_techniques", []):
                technique_ids.append(technique["id"])
        
        if not technique_ids:
            return "https://mitre-attack.github.io/attack-navigator/"
        
        # Create a simple layer for Navigator
        layer = {
            "name": "STRIDE-GPT Attack Tree",
            "versions": {"attack": "14", "navigator": "4.8.1", "layer": "4.4"},
            "domain": "enterprise-attack",
            "description": f"Attack tree techniques - Generated {datetime.now().strftime('%Y-%m-%d')}",
            "techniques": [{"techniqueID": tid, "color": "#ff6666", "enabled": True} 
                          for tid in set(technique_ids)]
        }
        
        # In a real implementation, you'd upload this to a service or encode it
        # For now, return the base Navigator URL
        return "https://mitre-attack.github.io/attack-navigator/"


def display_enhanced_attack_tree(attack_tree_data: Dict) -> None:
    """Display enhanced attack tree in Streamlit UI"""
    
    st.markdown("## 🌳 Enhanced Attack Tree with MITRE ATT&CK Integration")
    
    # Display summary statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        threat_count = len(attack_tree_data["enhanced_threats"])
        st.metric("Total Threats", threat_count)
    
    with col2:
        all_techniques = []
        for threat in attack_tree_data["enhanced_threats"]:
            all_techniques.extend(threat.get("mitre_techniques", []))
        unique_techniques = len(set(t["id"] for t in all_techniques))
        st.metric("MITRE Techniques", unique_techniques)
    
    with col3:
        tactics = set()
        for technique in all_techniques:
            tactics.update(technique.get("tactics", []))
        st.metric("ATT&CK Tactics", len(tactics))
    
    with col4:
        high_impact = sum(1 for threat in attack_tree_data["enhanced_threats"] 
                         if "High" in threat.get("Potential Impact", ""))
        st.metric("High Impact Threats", high_impact)
    
    # Display visualization options
    st.markdown("### 📊 Visualization Options")
    
    viz_option = st.selectbox(
        "Choose visualization type:",
        ["Interactive Graph", "Mermaid Diagram", "Attack Tree Report"]
    )
    
    if viz_option == "Interactive Graph":
        st.plotly_chart(attack_tree_data["plotly_graph"], use_container_width=True)
        
    elif viz_option == "Mermaid Diagram":
        st.markdown("```mermaid")
        st.markdown(attack_tree_data["mermaid_diagram"])
        st.markdown("```")
        
    elif viz_option == "Attack Tree Report":
        st.markdown(attack_tree_data["report"])
    
    # Add MITRE Navigator link
    st.markdown("### 🗺️ MITRE ATT&CK Navigator")
    st.markdown(f"[View techniques in ATT&CK Navigator]({attack_tree_data['mitre_navigator_url']})")
    
    # Add export options
    st.markdown("### 📥 Export Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Download Report"):
            st.download_button(
                label="Download Attack Tree Report",
                data=attack_tree_data["report"],
                file_name=f"attack_tree_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
    
    with col2:
        if st.button("🔗 Export Navigator Layer"):
            # Create Navigator layer JSON
            layer_json = json.dumps(attack_tree_data.get("navigator_layer", {}), indent=2)
            st.download_button(
                label="Download Navigator Layer",
                data=layer_json,
                file_name=f"attack_navigator_layer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            ) 