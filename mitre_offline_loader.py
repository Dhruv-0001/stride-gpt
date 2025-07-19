"""
MITRE ATT&CK Offline Data Loader

This module provides offline access to MITRE ATT&CK data using pre-downloaded files.
It serves as a fallback when the TAXII server is unavailable or for improved performance.

Usage:
    from mitre_offline_loader import MITREOfflineLoader
    
    loader = MITREOfflineLoader()
    techniques = loader.get_techniques()
    tactics = loader.get_tactics()
"""

import json
import sqlite3
import gzip
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import streamlit as st


class MITREOfflineLoader:
    """Loads MITRE ATT&CK data from offline sources"""
    
    def __init__(self, data_dir: str = "mitre_data"):
        self.data_dir = Path(data_dir)
        self.techniques = {}
        self.tactics = {}
        self.mitigations = {}
        self.groups = {}
        self.software = {}
        self.metadata = {}
        
        # Try to load data from available sources
        self._load_data()
    
    def _load_data(self):
        """Load data from available offline sources"""
        
        # Try loading from SQLite first (fastest)
        if self._load_from_sqlite():
            return
        
        # Try loading from JSON files
        if self._load_from_json():
            return
        
        # Try loading from compressed JSON
        if self._load_from_compressed_json():
            return
        
        # Try loading from embedded data
        if self._load_from_embedded_data():
            return
        
        # If all else fails, use minimal hardcoded data
        self._load_minimal_data()
    
    def _load_from_sqlite(self) -> bool:
        """Load data from SQLite database"""
        db_path = self.data_dir / "mitre_attack.db"
        
        if not db_path.exists():
            return False
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # Load techniques
                cursor.execute("SELECT mitre_id, name, description, platforms, tactics, url, detection, version FROM techniques")
                for row in cursor.fetchall():
                    mitre_id, name, desc, platforms, tactics, url, detection, version = row
                    self.techniques[mitre_id] = {
                        "name": name,
                        "description": desc,
                        "platforms": json.loads(platforms) if platforms else [],
                        "tactics": [{"phase_name": t} for t in json.loads(tactics)] if tactics else [],
                        "url": url,
                        "detection": detection,
                        "version": version,
                        "mitre_id": mitre_id
                    }
                
                # Load tactics
                cursor.execute("SELECT mitre_id, name, description, short_name, url FROM tactics")
                for row in cursor.fetchall():
                    mitre_id, name, desc, short_name, url = row
                    self.tactics[mitre_id] = {
                        "name": name,
                        "description": desc,
                        "short_name": short_name,
                        "url": url,
                        "mitre_id": mitre_id
                    }
                
                # Load mitigations
                cursor.execute("SELECT mitre_id, name, description, url, version FROM mitigations")
                for row in cursor.fetchall():
                    mitre_id, name, desc, url, version = row
                    self.mitigations[mitre_id] = {
                        "name": name,
                        "description": desc,
                        "url": url,
                        "version": version,
                        "mitre_id": mitre_id
                    }
                
                # Load groups
                cursor.execute("SELECT mitre_id, name, description, aliases, url FROM groups")
                for row in cursor.fetchall():
                    mitre_id, name, desc, aliases, url = row
                    self.groups[mitre_id] = {
                        "name": name,
                        "description": desc,
                        "aliases": json.loads(aliases) if aliases else [],
                        "url": url,
                        "mitre_id": mitre_id
                    }
                
                # Load software
                cursor.execute("SELECT mitre_id, name, description, type, platforms, aliases, url FROM software")
                for row in cursor.fetchall():
                    mitre_id, name, desc, sw_type, platforms, aliases, url = row
                    self.software[mitre_id] = {
                        "name": name,
                        "description": desc,
                        "type": sw_type,
                        "platforms": json.loads(platforms) if platforms else [],
                        "aliases": json.loads(aliases) if aliases else [],
                        "url": url,
                        "mitre_id": mitre_id
                    }
                
                # Load metadata
                cursor.execute("SELECT key, value FROM metadata")
                for key, value in cursor.fetchall():
                    try:
                        self.metadata[key] = json.loads(value)
                    except:
                        self.metadata[key] = value
            
            print("✅ Loaded MITRE data from SQLite database")
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to load from SQLite: {e}")
            return False
    
    def _load_from_json(self) -> bool:
        """Load data from JSON files"""
        json_dir = self.data_dir / "json"
        
        if not json_dir.exists():
            return False
        
        try:
            # Load each data type
            for data_type in ["techniques", "tactics", "mitigations", "groups", "software"]:
                file_path = json_dir / f"{data_type}.json"
                if file_path.exists():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        setattr(self, data_type, json.load(f))
            
            # Load metadata
            metadata_path = self.data_dir / "metadata.json"
            if metadata_path.exists():
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
            
            print("✅ Loaded MITRE data from JSON files")
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to load from JSON: {e}")
            return False
    
    def _load_from_compressed_json(self) -> bool:
        """Load data from compressed JSON files"""
        compressed_dir = self.data_dir / "compressed"
        
        if not compressed_dir.exists():
            return False
        
        try:
            # Load each data type
            for data_type in ["techniques", "tactics", "mitigations", "groups", "software"]:
                file_path = compressed_dir / f"{data_type}.json.gz"
                if file_path.exists():
                    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                        setattr(self, data_type, json.load(f))
            
            print("✅ Loaded MITRE data from compressed JSON files")
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to load from compressed JSON: {e}")
            return False
    
    def _load_from_embedded_data(self) -> bool:
        """Load data from embedded Python file"""
        try:
            from mitre_embedded_data import EMBEDDED_MITRE_DATA
            
            self.techniques = EMBEDDED_MITRE_DATA.get("techniques", {})
            self.tactics = EMBEDDED_MITRE_DATA.get("tactics", {})
            self.mitigations = EMBEDDED_MITRE_DATA.get("mitigations", {})
            self.groups = EMBEDDED_MITRE_DATA.get("groups", {})
            self.software = EMBEDDED_MITRE_DATA.get("software", {})
            self.metadata = EMBEDDED_MITRE_DATA.get("metadata", {})
            
            print("✅ Loaded MITRE data from embedded data")
            return True
            
        except ImportError:
            return False
        except Exception as e:
            print(f"⚠️  Failed to load embedded data: {e}")
            return False
    
    def _load_minimal_data(self):
        """Load minimal hardcoded data as last resort"""
        print("⚠️  Using minimal hardcoded MITRE data")
        
        # Essential techniques for common application threats
        self.techniques = {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                "tactics": [{"phase_name": "initial-access"}],
                "platforms": ["Linux", "Windows", "macOS", "Network"],
                "url": "https://attack.mitre.org/techniques/T1190/",
                "mitre_id": "T1190"
            },
            "T1078": {
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "tactics": [{"phase_name": "defense-evasion"}, {"phase_name": "persistence"}, {"phase_name": "privilege-escalation"}, {"phase_name": "initial-access"}],
                "platforms": ["Linux", "macOS", "Windows", "Office 365", "Azure AD", "SaaS", "Google Workspace"],
                "url": "https://attack.mitre.org/techniques/T1078/",
                "mitre_id": "T1078"
            },
            "T1110": {
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "tactics": [{"phase_name": "credential-access"}],
                "platforms": ["Linux", "macOS", "Windows", "Office 365", "Azure AD", "SaaS", "Google Workspace"],
                "url": "https://attack.mitre.org/techniques/T1110/",
                "mitre_id": "T1110"
            },
            "T1499": {
                "name": "Endpoint Denial of Service",
                "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.",
                "tactics": [{"phase_name": "impact"}],
                "platforms": ["Linux", "macOS", "Windows"],
                "url": "https://attack.mitre.org/techniques/T1499/",
                "mitre_id": "T1499"
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "tactics": [{"phase_name": "exfiltration"}],
                "platforms": ["Linux", "macOS", "Windows"],
                "url": "https://attack.mitre.org/techniques/T1041/",
                "mitre_id": "T1041"
            }
        }
        
        # Essential tactics
        self.tactics = {
            "TA0001": {
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network.",
                "short_name": "initial-access",
                "url": "https://attack.mitre.org/tactics/TA0001",
                "mitre_id": "TA0001"
            },
            "TA0006": {
                "name": "Credential Access",
                "description": "The adversary is trying to steal account names and passwords.",
                "short_name": "credential-access",
                "url": "https://attack.mitre.org/tactics/TA0006",
                "mitre_id": "TA0006"
            },
            "TA0010": {
                "name": "Exfiltration",
                "description": "The adversary is trying to steal data.",
                "short_name": "exfiltration",
                "url": "https://attack.mitre.org/tactics/TA0010",
                "mitre_id": "TA0010"
            },
            "TA0040": {
                "name": "Impact",
                "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                "short_name": "impact",
                "url": "https://attack.mitre.org/tactics/TA0040",
                "mitre_id": "TA0040"
            }
        }
        
        # Essential mitigations
        self.mitigations = {
            "M1050": {
                "name": "Exploit Protection",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring.",
                "url": "https://attack.mitre.org/mitigations/M1050/",
                "mitre_id": "M1050"
            },
            "M1032": {
                "name": "Multi-factor Authentication",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.",
                "url": "https://attack.mitre.org/mitigations/M1032/",
                "mitre_id": "M1032"
            }
        }
        
        self.metadata = {
            "version": "minimal",
            "source": "hardcoded",
            "download_date": "N/A"
        }
    
    def get_techniques(self) -> Dict[str, Any]:
        """Get all techniques"""
        return self.techniques
    
    def get_tactics(self) -> Dict[str, Any]:
        """Get all tactics"""
        return self.tactics
    
    def get_mitigations(self) -> Dict[str, Any]:
        """Get all mitigations"""
        return self.mitigations
    
    def get_groups(self) -> Dict[str, Any]:
        """Get all groups"""
        return self.groups
    
    def get_software(self) -> Dict[str, Any]:
        """Get all software"""
        return self.software
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about the data"""
        return self.metadata
    
    def is_data_available(self) -> bool:
        """Check if MITRE data is available"""
        return len(self.techniques) > 0 and len(self.tactics) > 0
    
    def get_data_source(self) -> str:
        """Get the source of the current data"""
        return self.metadata.get("source", "unknown")
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded data"""
        return {
            "techniques": len(self.techniques),
            "tactics": len(self.tactics),
            "mitigations": len(self.mitigations),
            "groups": len(self.groups),
            "software": len(self.software)
        }


@st.cache_resource
def get_offline_mitre_data():
    """Cached function to get offline MITRE data"""
    return MITREOfflineLoader()


# Quick test function
def test_offline_loader():
    """Test the offline loader functionality"""
    loader = MITREOfflineLoader()
    stats = loader.get_stats()
    
    print("MITRE Offline Loader Test Results:")
    print(f"Data Source: {loader.get_data_source()}")
    print(f"Techniques: {stats['techniques']}")
    print(f"Tactics: {stats['tactics']}")
    print(f"Mitigations: {stats['mitigations']}")
    print(f"Groups: {stats['groups']}")
    print(f"Software: {stats['software']}")
    
    return loader.is_data_available()


if __name__ == "__main__":
    test_offline_loader()