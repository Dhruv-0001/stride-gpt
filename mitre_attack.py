"""
MITRE ATT&CK Integration Module

This module provides functionality to:
1. Fetch MITRE ATT&CK data using TAXII2 client
2. Cache data locally for performance
3. Map STRIDE threats to ATT&CK techniques
4. Generate enhanced threat models with ATT&CK context
5. Provide citations and references
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd
import streamlit as st

# Import offline loader (required for offline-only mode)
from mitre_offline_loader import MITREOfflineLoader


class MITREAttackData:
    """Class to handle MITRE ATT&CK data loading from offline sources"""
    
    def __init__(self, data_dir: str = "mitre_data"):
        self.data_dir = data_dir
        
        # Initialize data containers
        self.techniques = {}
        self.tactics = {}
        self.mitigations = {}
        self.groups = {}
        self.software = {}
        self.metadata = {}

    
    def initialize_attack_data(self) -> bool:
        """Initialize MITRE ATT&CK data from offline sources only"""
        
        
        try:
            # Use offline loader
            offline_loader = MITREOfflineLoader(self.data_dir)
            
            if not offline_loader.is_data_available():
                st.error("No offline MITRE data found in the mitre_data directory.")
                st.info("""
                **Offline MITRE data not found. Please ensure:**
                
                1. The `mitre_data/` directory exists
                2. MITRE data files are present (JSON or SQLite format)
                3. Data was downloaded correctly
                
                Using embedded fallback data for basic functionality.
                """)
                # Use embedded data as fallback
                return self._use_embedded_fallback()
            
            # Load data from offline source
            self.techniques = offline_loader.get_techniques()
            self.tactics = offline_loader.get_tactics()
            self.mitigations = offline_loader.get_mitigations()
            self.groups = offline_loader.get_groups()
            self.software = offline_loader.get_software()
            self.metadata = offline_loader.get_metadata()
            
            stats = offline_loader.get_stats()
            data_source = offline_loader.get_data_source()
            
            return True
            
        except Exception as e:
            st.warning(f"Error loading offline data: {e}")
            st.info("Using embedded fallback data...")
            return self._use_embedded_fallback()
    
    def _use_embedded_fallback(self) -> bool:
        """Use embedded MITRE data as fallback"""
        try:
            from mitre_embedded_data import EMBEDDED_MITRE_DATA
            
            self.techniques = EMBEDDED_MITRE_DATA.get("techniques", {})
            self.tactics = EMBEDDED_MITRE_DATA.get("tactics", {})
            self.mitigations = EMBEDDED_MITRE_DATA.get("mitigations", {})
            self.groups = EMBEDDED_MITRE_DATA.get("groups", {})
            self.software = EMBEDDED_MITRE_DATA.get("software", {})
            self.metadata = EMBEDDED_MITRE_DATA.get("metadata", {})
            
            st.info(f"Embedded data: {len(self.techniques)} techniques, {len(self.tactics)} tactics")
            
            return True
            
        except Exception as e:
            st.error(f"Failed to load embedded data: {e}")
            return False
    



class STRIDEMITREMapper:
    """Class to map STRIDE threats to MITRE ATT&CK techniques"""
    
    def __init__(self, attack_data: MITREAttackData):
        self.attack_data = attack_data
        
        # STRIDE to ATT&CK tactic mapping
        self.stride_to_tactics = {
            "Spoofing": ["initial-access", "credential-access", "defense-evasion"],
            "Tampering": ["persistence", "defense-evasion", "impact"],
            "Repudiation": ["defense-evasion", "impact"],
            "Information Disclosure": ["collection", "exfiltration"],
            "Denial of Service": ["impact"],
            "Elevation of Privilege": ["privilege-escalation", "lateral-movement"]
        }
        
        # Common technique mappings for application security
        self.app_security_mappings = {
            "web_application": {
                "Spoofing": ["T1078", "T1110", "T1133", "T1199"],  # Valid Accounts, Brute Force, External Remote Services, Trusted Relationship
                "Tampering": ["T1190", "T1203", "T1211", "T1068"],  # Exploit Public-Facing Application, Exploitation for Client Execution, Exploitation for Defense Evasion, Exploitation for Privilege Escalation
                "Repudiation": ["T1070", "T1036", "T1562"],  # Indicator Removal on Host, Masquerading, Impair Defenses
                "Information Disclosure": ["T1005", "T1039", "T1041", "T1567"],  # Data from Local System, Data from Network Shared Drive, Exfiltration Over C2 Channel, Exfiltration Over Web Service
                "Denial of Service": ["T1499", "T1498"],  # Endpoint Denial of Service, Network Denial of Service
                "Elevation of Privilege": ["T1068", "T1055", "T1134"]  # Exploitation for Privilege Escalation, Process Injection, Access Token Manipulation
            },
            "api": {
                "Spoofing": ["T1078", "T1110", "T1556"],  # Valid Accounts, Brute Force, Modify Authentication Process
                "Tampering": ["T1190", "T1565"],  # Exploit Public-Facing Application, Data Manipulation
                "Information Disclosure": ["T1041", "T1567", "T1530"],  # Exfiltration Over C2 Channel, Exfiltration Over Web Service, Data from Cloud Storage Object
                "Denial of Service": ["T1499", "T1498"],  # Endpoint Denial of Service, Network Denial of Service
                "Elevation of Privilege": ["T1548", "T1134"]  # Abuse Elevation Control Mechanism, Access Token Manipulation
            },
            "mobile_application": {
                "Spoofing": ["T1456", "T1444", "T1475"],  # Drive-by Compromise, Masquerade as Legitimate Application, Deliver Malicious App via Authorized App Store
                "Tampering": ["T1401", "T1445", "T1576"],  # Device Administrator Permissions, Masquerade as Legitimate Application, Compromise Application Executable
                "Information Disclosure": ["T1533", "T1422", "T1432"],  # Data from Local System, System Information Discovery, Access Contact List
                "Denial of Service": ["T1582", "T1464"],  # SMS Control, Network Denial of Service
                "Elevation of Privilege": ["T1401", "T1404"]  # Device Administrator Permissions, Exploit TEE Vulnerability
            }
        }
    
    def map_stride_to_mitre(self, stride_threats: List[Dict], app_type: str = "web_application") -> List[Dict]:
        """
        Map STRIDE threats to MITRE ATT&CK techniques
        
        Args:
            stride_threats: List of STRIDE threat dictionaries
            app_type: Type of application (web_application, api, mobile_application, etc.)
            
        Returns:
            List of enhanced threat dictionaries with MITRE mappings
        """
        enhanced_threats = []
        
        for threat in stride_threats:
            threat_type = threat.get("Threat Type", "")
            enhanced_threat = threat.copy()
            
            # Get relevant ATT&CK techniques
            mitre_techniques = self._get_relevant_techniques(threat_type, threat, app_type)
            
            enhanced_threat["mitre_techniques"] = mitre_techniques
            enhanced_threat["mitre_tactics"] = self._get_relevant_tactics(threat_type)
            enhanced_threat["mitre_url"] = self._generate_attack_navigator_url(mitre_techniques)
            
            enhanced_threats.append(enhanced_threat)
        
        return enhanced_threats
    
    def _get_relevant_techniques(self, threat_type: str, threat_details: Dict, app_type: str) -> List[Dict]:
        """Get relevant MITRE techniques for a STRIDE threat"""
        techniques = []
        
        # Get predefined mappings for app type
        app_mappings = self.app_security_mappings.get(app_type, self.app_security_mappings["web_application"])
        technique_ids = app_mappings.get(threat_type, [])
        
        for technique_id in technique_ids:
            if technique_id in self.attack_data.techniques:
                technique_data = self.attack_data.techniques[technique_id]
                # Ensure proper MITRE technique URL
                technique_url = technique_data.get("url", "")
                if not technique_url or technique_url == "#":
                    technique_url = f"https://attack.mitre.org/techniques/{technique_id}/"
                
                techniques.append({
                    "id": technique_id,
                    "name": technique_data["name"],
                    "description": technique_data["description"][:200] + "..." if len(technique_data["description"]) > 200 else technique_data["description"],
                    "url": technique_url,
                    "tactics": [phase.get("phase_name", "") for phase in technique_data.get("tactics", [])],
                    "platforms": technique_data.get("platforms", [])
                })
        
        return techniques
    
    def _get_relevant_tactics(self, threat_type: str) -> List[str]:
        """Get relevant MITRE tactics for a STRIDE threat"""
        return self.stride_to_tactics.get(threat_type, [])
    
    def _generate_attack_navigator_url(self, techniques: List[Dict]) -> str:
        """Generate ATT&CK Navigator URL for visualization"""
        # The Navigator requires a proper layer file to be uploaded
        # For now, just return the base Navigator URL since we provide export functionality
        return "https://mitre-attack.github.io/attack-navigator/"
    
    def generate_mitre_mitigations(self, threat_techniques: List[Dict]) -> List[Dict]:
        """Generate MITRE-based mitigations for threats"""
        mitigations = []
        
        for technique in threat_techniques:
            technique_id = technique["id"]
            
            # Find related mitigations
            related_mitigations = self._find_mitigations_for_technique(technique_id)
            
            for mitigation in related_mitigations:
                # Ensure proper MITRE mitigation URL
                mitigation_url = mitigation.get("url", "")
                if not mitigation_url or mitigation_url == "#":
                    mitigation_url = f"https://attack.mitre.org/mitigations/{mitigation['mitre_id']}/"
                
                mitigations.append({
                    "technique_id": technique_id,
                    "technique_name": technique["name"],
                    "technique_url": technique["url"],
                    "mitigation_id": mitigation["mitre_id"],
                    "mitigation_name": mitigation["name"],
                    "mitigation_description": mitigation["description"],
                    "mitigation_url": mitigation_url
                })
        
        return mitigations
    
    def _find_mitigations_for_technique(self, technique_id: str) -> List[Dict]:
        """Find mitigations that address a specific technique"""
        # This would typically require querying relationships in STIX data
        # For now, we'll return general mitigations based on technique categories
        general_mitigations = []
        
        # Add some common mitigations based on technique ID patterns
        if technique_id.startswith("T10"):  # Initial Access
            general_mitigations.extend([
                self.attack_data.mitigations.get("M1042", {}),  # Disable or Remove Feature or Program
                self.attack_data.mitigations.get("M1050", {}),  # Exploit Protection
            ])
        elif technique_id.startswith("T11"):  # Execution
            general_mitigations.extend([
                self.attack_data.mitigations.get("M1038", {}),  # Execution Prevention
                self.attack_data.mitigations.get("M1049", {}),  # Antivirus/Antimalware
            ])
        
        return [m for m in general_mitigations if m]


def create_mitre_enhanced_prompt(app_type: str, authentication: str, internet_facing: str, 
                                sensitive_data: str, app_input: str, mitre_context: str = "") -> str:
    """Create an enhanced prompt that includes MITRE ATT&CK context"""
    
    base_prompt = f"""
Act as a cyber security expert with more than 20 years experience of using both the STRIDE threat modelling methodology and MITRE ATT&CK framework to produce comprehensive threat models for a wide range of applications.

Your task is to analyze the provided application details and produce a list of specific threats that are mapped to real-world attack techniques documented in the MITRE ATT&CK framework.

APPLICATION DETAILS:
- Application Type: {app_type}
- Authentication Methods: {authentication}
- Internet Facing: {internet_facing}
- Sensitive Data: {sensitive_data}
- Application Description: {app_input}

{mitre_context}

For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), provide specific threats that:

1. Are realistic and applicable to the described application
2. Reference specific MITRE ATT&CK techniques where applicable
3. Include the potential impact and likelihood
4. Provide actionable mitigation recommendations with MITRE references

Format your response as a JSON object with the following structure:
{{
    "threat_model": [
        {{
            "Threat Type": "STRIDE category",
            "Scenario": "Detailed threat scenario",
            "Potential Impact": "Impact description",
            "Likelihood": "High/Medium/Low",
            "MITRE_Techniques": ["T1234", "T5678"],
            "MITRE_Tactics": ["tactic-name"],
            "Evidence_Sources": ["source1", "source2"],
            "Mitigation_References": ["M1234", "M5678"]
        }}
    ],
    "improvement_suggestions": [
        "suggestion1",
        "suggestion2"
    ],
    "mitre_context": {{
        "framework_version": "ATT&CK v14",
        "analysis_date": "{datetime.now().strftime('%Y-%m-%d')}",
        "applicable_tactics": ["list of relevant tactics"],
        "risk_factors": ["factor1", "factor2"]
    }}
}}

Ensure all MITRE technique and mitigation IDs are valid and current. Provide citations and URLs where appropriate.
"""
    
    return base_prompt


# Initialize global MITRE data instance
@st.cache_resource
def get_mitre_attack_data():
    """Get cached MITRE ATT&CK data instance"""
    mitre_data = MITREAttackData()
    if mitre_data.initialize_attack_data():
        return mitre_data
    return None


def display_mitre_enhanced_threats(enhanced_threats: List[Dict]) -> None:
    """Display enhanced threats with MITRE context in Streamlit"""
    
    st.markdown("## Enhanced Threat Model with MITRE ATT&CK Mapping")
    
    for i, threat in enumerate(enhanced_threats, 1):
        threat_id = threat.get('Threat ID', f'STR-{i:03d}')
        component = threat.get('Component', 'Not Specified')
        
        with st.expander(f"**{threat_id}** - {threat['Threat Type']} - {threat['Scenario'][:40]}..."):
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Threat ID:** {threat_id}")
                st.markdown(f"**Component:** {component}")
                st.markdown(f"**Scenario:** {threat['Scenario']}")
                st.markdown(f"**Potential Impact:** {threat['Potential Impact']}")
                
                if "Likelihood" in threat:
                    likelihood_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
                    color = likelihood_color.get(threat["Likelihood"], "⚪")
                    st.markdown(f"**Likelihood:** {color} {threat['Likelihood']}")
            
            with col2:
                if "mitre_techniques" in threat and threat["mitre_techniques"]:
                    st.markdown("**MITRE ATT&CK Techniques:**")
                    for technique in threat["mitre_techniques"]:
                        st.markdown(f"- [{technique['id']} - {technique['name']}]({technique['url']})")
                
                if "mitre_tactics" in threat and threat["mitre_tactics"]:
                    st.markdown("**Tactics:**")
                    tactics_str = ", ".join(threat["mitre_tactics"])
                    st.markdown(f"*{tactics_str}*")
            
            # Add MITRE Navigator link if available
            # if "mitre_url" in threat:
            #     st.markdown(f"[View in ATT&CK Navigator]({threat['mitre_url']})")


def export_to_attack_navigator(enhanced_threats: List[Dict]) -> Dict:
    """Export threat model to ATT&CK Navigator format"""
    
    layer = {
        "name": "STRIDE-GPT Threat Model",
        "versions": {
            "attack": "14",
            "navigator": "4.8.1",
            "layer": "4.4"
        },
        "domain": "enterprise-attack",
        "description": f"Threat model generated by STRIDE-GPT on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "techniques": []
    }
    
    for threat in enhanced_threats:
        if "mitre_techniques" in threat:
            for technique in threat["mitre_techniques"]:
                layer["techniques"].append({
                    "techniqueID": technique["id"],
                    "color": "#ff6666",
                    "comment": f"STRIDE: {threat['Threat Type']} - {threat['Scenario'][:100]}...",
                    "enabled": True,
                    "metadata": [{
                        "name": "STRIDE Category",
                        "value": threat["Threat Type"]
                    }, {
                        "name": "Scenario",
                        "value": threat["Scenario"]
                    }]
                })
    
    return layer 