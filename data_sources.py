"""
Data fetching modules for security assessment
"""
import requests
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class ProductHuntAPI:
    """Fetch product information from ProductHunt API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.producthunt.com/v2/api/graphql"
        
    def search_product(self, product_name: str) -> Optional[Dict[str, Any]]:
        """Search for a product on ProductHunt"""
        
        query = """
        query($term: String!) {
          posts(first: 5, postedAfter: "2020-01-01", order: VOTES) {
            edges {
              node {
                id
                name
                tagline
                description
                url
                website
                votesCount
                commentsCount
                createdAt
                productLinks {
                  url
                  type
                }
                topics {
                  edges {
                    node {
                      name
                    }
                  }
                }
                makers {
                  edges {
                    node {
                      name
                      url
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                self.base_url,
                json={"query": query, "variables": {"term": product_name}},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                products = data.get('data', {}).get('posts', {}).get('edges', [])
                
                # Find best match
                for edge in products:
                    node = edge.get('node', {})
                    if product_name.lower() in node.get('name', '').lower():
                        return self._format_product_data(node)
                
                # Return first result if no exact match
                if products:
                    return self._format_product_data(products[0].get('node', {}))
                    
            logger.warning(f"ProductHunt API returned status {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"Error fetching from ProductHunt: {e}")
            return None
    
    def _format_product_data(self, node: Dict) -> Dict[str, Any]:
        """Format ProductHunt data"""
        topics = [edge['node']['name'] for edge in node.get('topics', {}).get('edges', [])]
        makers = [edge['node']['name'] for edge in node.get('makers', {}).get('edges', [])]
        
        return {
            "name": node.get('name'),
            "tagline": node.get('tagline'),
            "description": node.get('description'),
            "url": node.get('url'),
            "website": node.get('website'),
            "votes": node.get('votesCount', 0),
            "comments": node.get('commentsCount', 0),
            "created_at": node.get('createdAt'),
            "topics": topics,
            "makers": makers,
            "source": "ProductHunt"
        }


class OpenCVEAPI:
    """Fetch CVE information from OpenCVE API"""
    
    def __init__(self):
        self.base_url = "https://www.opencve.io/api"
        
    def search_cves(self, vendor: str, product: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for CVEs by vendor and optionally product"""
        
        try:
            # Search for vendor first
            cves = []
            params = {
                "vendor": vendor.lower(),
                "sort": "cvss",
                "order": "desc"
            }
            
            if product:
                params["product"] = product.lower()
            
            response = requests.get(
                f"{self.base_url}/cve",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                cves = data if isinstance(data, list) else []
                
                # Limit results
                cves = cves[:limit]
                
                # Format CVE data
                return [self._format_cve_data(cve) for cve in cves]
            else:
                logger.warning(f"OpenCVE API returned status {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching from OpenCVE: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE"""
        
        try:
            response = requests.get(
                f"{self.base_url}/cve/{cve_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                return self._format_cve_data(response.json())
            else:
                logger.warning(f"OpenCVE API returned status {response.status_code} for CVE {cve_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching CVE details: {e}")
            return None
    
    def _format_cve_data(self, cve: Dict) -> Dict[str, Any]:
        """Format CVE data"""
        return {
            "cve_id": cve.get('id'),
            "summary": cve.get('summary'),
            "cvss_v3": cve.get('cvss', {}).get('v3'),
            "cvss_v2": cve.get('cvss', {}).get('v2'),
            "severity": cve.get('cvss', {}).get('v3_severity') or cve.get('cvss', {}).get('v2_severity'),
            "published_date": cve.get('created_at'),
            "updated_date": cve.get('updated_at'),
            "vendors": cve.get('vendors', []),
            "cwes": cve.get('cwes', []),
            "references": cve.get('references', [])[:5],  # Limit references
            "source": "OpenCVE"
        }


class CISAKEVAPI:
    """Fetch Known Exploited Vulnerabilities from CISA KEV catalog"""
    
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._cache = None
        self._cache_time = None
        self._cache_duration = 3600  # 1 hour
        
    def get_kev_catalog(self) -> Dict[str, Any]:
        """Fetch the entire KEV catalog"""
        
        # Use cache if available and fresh
        if self._cache and self._cache_time:
            if (datetime.now().timestamp() - self._cache_time) < self._cache_duration:
                return self._cache
        
        try:
            response = requests.get(self.kev_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                self._cache = data
                self._cache_time = datetime.now().timestamp()
                return data
            else:
                logger.warning(f"CISA KEV API returned status {response.status_code}")
                return {"vulnerabilities": []}
                
        except Exception as e:
            logger.error(f"Error fetching CISA KEV catalog: {e}")
            return {"vulnerabilities": []}
    
    def search_kev(self, vendor: str, product: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search KEV catalog for specific vendor/product"""
        
        catalog = self.get_kev_catalog()
        vulnerabilities = catalog.get('vulnerabilities', [])
        
        results = []
        search_term = vendor.lower()
        product_term = product.lower() if product else None
        
        for vuln in vulnerabilities:
            vuln_name = vuln.get('vendorProject', '').lower() + ' ' + vuln.get('product', '').lower()
            
            # Check if vendor matches
            if search_term in vuln_name:
                # If product specified, check product match too
                if product_term:
                    if product_term in vuln_name:
                        results.append(self._format_kev_data(vuln))
                else:
                    results.append(self._format_kev_data(vuln))
        
        return results
    
    def _format_kev_data(self, vuln: Dict) -> Dict[str, Any]:
        """Format KEV data"""
        return {
            "cve_id": vuln.get('cveID'),
            "vendor_project": vuln.get('vendorProject'),
            "product": vuln.get('product'),
            "vulnerability_name": vuln.get('vulnerabilityName'),
            "description": vuln.get('shortDescription'),
            "required_action": vuln.get('requiredAction'),
            "due_date": vuln.get('dueDate'),
            "date_added": vuln.get('dateAdded'),
            "known_ransomware": vuln.get('knownRansomwareCampaignUse', 'Unknown'),
            "notes": vuln.get('notes', ''),
            "source": "CISA KEV"
        }


class WebSourceFetcher:
    """Fetch additional context from web sources"""
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
    
    def fetch_vendor_security_page(self, url: str) -> Optional[str]:
        """Attempt to fetch vendor security page content"""
        
        # Common security page paths
        security_paths = [
            "/security",
            "/trust",
            "/security-practices",
            "/responsible-disclosure",
            "/bug-bounty"
        ]
        
        try:
            # Try the main URL first
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.text[:50000]  # Limit content size
                
        except Exception as e:
            logger.debug(f"Could not fetch {url}: {e}")
        
        return None
