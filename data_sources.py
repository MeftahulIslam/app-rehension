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
    """Fetch CVE information from OpenCVE API with Basic Authentication"""
    
    def __init__(self, username: Optional[str] = None, password: Optional[str] = None):
        self.base_url = "https://app.opencve.io/api"
        self.username = username
        self.password = password
        self.auth = (username, password) if username and password else None
        
        if not self.auth:
            logger.warning("OpenCVE credentials not provided - API access may be limited")
        
    def search_cves(self, vendor: str, product: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for CVEs by vendor and optionally product using /cve endpoint"""
        
        try:
            all_cves = []
            page = 1
            max_pages = 10  # Limit to prevent excessive API calls
            
            # Extract clean vendor name (remove common suffixes)
            clean_vendor = self._extract_vendor_keyword(vendor)
            clean_product = self._extract_vendor_keyword(product) if product else None
            
            # Build query parameters - use product if available, otherwise use vendor
            params = {}
            
            if clean_product:
                # If product is specified, only search by product
                params["product"] = clean_product
                search_term = f"product={clean_product}"
            else:
                # Otherwise search by vendor
                params["vendor"] = clean_vendor
                search_term = f"vendor={clean_vendor}"
            
            headers = {"Accept": "application/json"}
            
            logger.info(f"Searching OpenCVE with {search_term}")
            
            while len(all_cves) < limit and page <= max_pages:
                params["page"] = page
                
                response = requests.get(
                    f"{self.base_url}/cve",
                    params=params,
                    auth=self.auth,
                    headers=headers,
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if isinstance(data, dict) and 'results' in data:
                        results = data.get('results', [])
                        
                        if not results:
                            logger.info("No more results found")
                            break
                        
                        all_cves.extend(results)
                        logger.info(f"Fetched {len(results)} CVEs from page {page} (total: {len(all_cves)})")
                        
                        # Check if there are more pages
                        if not data.get('next') or len(all_cves) >= limit:
                            break
                        
                        page += 1
                    else:
                        logger.warning("Unexpected response format from OpenCVE")
                        break
                        
                elif response.status_code == 401:
                    logger.error("OpenCVE authentication failed - check username and password")
                    return []
                elif response.status_code == 404:
                    logger.info("No results found or reached end of pages")
                    break
                else:
                    logger.warning(f"OpenCVE API returned status {response.status_code}")
                    break
            
            # Limit results to requested amount
            all_cves = all_cves[:limit]
            logger.info(f"Total CVEs returned: {len(all_cves)}")
            
            # Format CVE data
            formatted_cves = [self._format_cve_data(cve, detailed=False) for cve in all_cves]
            return formatted_cves
                
        except Exception as e:
            logger.error(f"Error fetching from OpenCVE: {e}", exc_info=True)
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE using /cve/<id> endpoint"""
        
        try:
            headers = {"Accept": "application/json"}
            
            logger.info(f"Fetching details for {cve_id}")
            
            response = requests.get(
                f"{self.base_url}/cve/{cve_id}",
                auth=self.auth,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return self._format_cve_data(response.json(), detailed=True)
            elif response.status_code == 401:
                logger.error("OpenCVE authentication failed - check username and password")
                return None
            elif response.status_code == 404:
                logger.warning(f"CVE {cve_id} not found")
                return None
            else:
                logger.warning(f"OpenCVE API returned status {response.status_code} for CVE {cve_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching CVE details: {e}")
            return None
    
    def _extract_vendor_keyword(self, name: str) -> str:
        """Extract the core vendor/product keyword from a full company name"""
        if not name:
            return ""
        
        name_lower = name.lower().strip()
        
        # List of common suffixes to remove
        suffixes_to_remove = [
            ' inc.', ' inc', ' incorporated',
            ' llc', ' ltd', ' ltd.',
            ' corporation', ' corp', ' corp.',
            ' company', ' co', ' co.',
            ' limited',
            ' labs',
            ' technologies', ' technology', ' tech',
            ' software',
            ' systems',
            ' solutions',
            ' group',
            ' international',
            ' enterprises',
            ' holdings'
        ]
        
        # Remove suffixes
        for suffix in suffixes_to_remove:
            if name_lower.endswith(suffix):
                name_lower = name_lower[:-len(suffix)].strip()
                break  # Only remove one suffix
        
        # Remove common prefixes
        prefixes_to_remove = ['the ']
        for prefix in prefixes_to_remove:
            if name_lower.startswith(prefix):
                name_lower = name_lower[len(prefix):].strip()
        
        # Take the first word if multiple words remain (e.g., "notion labs" -> "notion")
        words = name_lower.split()
        if len(words) > 1:
            # Keep first word unless it's very generic
            generic_words = ['open', 'free', 'gnu', 'apache']
            if words[0] not in generic_words:
                return words[0]
        
        return name_lower
    
    def _format_cve_data(self, cve: Dict, detailed: bool = False) -> Dict[str, Any]:
        """Format CVE data from OpenCVE API response"""
        
        # Basic fields available in both list and detail views
        formatted = {
            "cve_id": cve.get('cve_id'),
            "summary": cve.get('description', ''),
            "published_date": cve.get('created_at'),
            "updated_date": cve.get('updated_at'),
            "source": "OpenCVE"
        }
        
        # Additional fields for detailed view
        if detailed:
            # Extract CVSS scores from metrics
            metrics = cve.get('metrics', {})
            cvss_v3_1 = metrics.get('cvssV3_1', {}).get('data', {})
            cvss_v3_0 = metrics.get('cvssV3_0', {}).get('data', {})
            cvss_v2_0 = metrics.get('cvssV2_0', {}).get('data', {})
            
            # Get the best CVSS score available
            cvss_score = cvss_v3_1.get('score') or cvss_v3_0.get('score') or cvss_v2_0.get('score')
            cvss_vector = cvss_v3_1.get('vector') or cvss_v3_0.get('vector') or cvss_v2_0.get('vector')
            
            # Determine severity
            severity = None
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            formatted.update({
                "title": cve.get('title', ''),
                "cvss_v3": cvss_score,
                "cvss_vector": cvss_vector,
                "cvss_v2": cvss_v2_0.get('score'),
                "severity": severity,
                "vendors": cve.get('vendors', []),
                "cwes": cve.get('weaknesses', []),
                "metrics": metrics
            })
        else:
            # For list view, we don't have full metrics, so set defaults
            formatted.update({
                "cvss_v3": None,
                "cvss_v2": None,
                "cvss_vector": None,
                "severity": None,
                "vendors": [],
                "cwes": []
            })
        
        return formatted


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
