"""
Core assessment engine that orchestrates data gathering and analysis
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from data_sources import ProductHuntAPI, OpenCVEAPI, CISAKEVAPI
from llm_analyzer import GeminiAnalyzer
from database import AssessmentCache

logger = logging.getLogger(__name__)


class SecurityAssessor:
    """Main assessment engine"""
    
    def __init__(self, config):
        self.config = config
        
        # Initialize components
        self.product_hunt = ProductHuntAPI(config.PRODUCTHUNT_API_KEY) if config.PRODUCTHUNT_API_KEY else None
        self.opencve = OpenCVEAPI(
            username=config.OPENCVE_USERNAME,
            password=config.OPENCVE_PASSWORD
        )
        self.cisa_kev = CISAKEVAPI()
        self.analyzer = GeminiAnalyzer(config.GEMINI_API_KEY, config.GEMINI_MODEL)
        self.cache = AssessmentCache(config.DATABASE_PATH)
        
        logger.info("SecurityAssessor initialized")
    
    def assess_product(self, input_text: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Main assessment workflow
        
        Args:
            input_text: Product name, vendor, or URL
            use_cache: Whether to use cached results if available
            
        Returns:
            Comprehensive security assessment
        """
        logger.info(f"Starting assessment for: {input_text}")
        
        # Check cache first
        if use_cache:
            cached = self.cache.get_assessment(input_text, max_age_hours=self.config.CACHE_EXPIRY_HOURS)
            if cached:
                logger.info(f"Returning cached assessment for: {input_text}")
                return cached
        
        # Step 1: Gather initial data
        logger.info("Step 1: Gathering product information")
        product_data = self._gather_product_data(input_text)
        
        # Step 2: Resolve entity
        logger.info("Step 2: Resolving entity identity")
        entity_info = self.analyzer.resolve_entity(input_text, product_data)
        
        product_name = entity_info.get('product_name')
        vendor = entity_info.get('vendor')
        
        logger.info(f"Resolved - Product: {product_name}, Vendor: {vendor}")
        
        # Step 3: Classify software
        logger.info("Step 3: Classifying software")
        classification = self.analyzer.classify_software(entity_info, product_data)
        
        # Step 4: Gather security data
        logger.info("Step 4: Gathering security data (CVE, KEV)")
        security_data = self._gather_security_data(vendor, product_name)
        
        # Step 5: Analyze vulnerabilities
        logger.info("Step 5: Analyzing vulnerabilities")
        vuln_analysis = self.analyzer.analyze_vulnerabilities(
            security_data['cves'],
            security_data['kevs']
        )
        
        # Step 6: Calculate trust score
        logger.info("Step 6: Calculating trust score")
        all_data = {
            'entity_info': entity_info,
            'classification': classification,
            'product_data': product_data,
            'security_data': security_data,
            'vuln_analysis': vuln_analysis
        }
        trust_score = self.analyzer.calculate_trust_score(all_data)
        
        # Step 7: Suggest alternatives
        logger.info("Step 7: Suggesting alternatives")
        alternatives = self.analyzer.suggest_alternatives(entity_info, classification, trust_score)
        
        # Step 8: Compile final assessment
        logger.info("Step 8: Compiling final assessment")
        assessment = self._compile_assessment(
            entity_info=entity_info,
            classification=classification,
            product_data=product_data,
            security_data=security_data,
            vuln_analysis=vuln_analysis,
            trust_score=trust_score,
            alternatives=alternatives
        )
        
        # Cache the result
        logger.info("Saving assessment to cache")
        self.cache.save_assessment(
            product_name=product_name,
            assessment_data=assessment,
            vendor=vendor,
            url=entity_info.get('url')
        )
        
        logger.info(f"Assessment complete for: {input_text}")
        return assessment
    
    def _gather_product_data(self, input_text: str) -> Optional[Dict[str, Any]]:
        """Gather product information from ProductHunt"""
        
        if not self.product_hunt:
            logger.warning("ProductHunt API not configured")
            return None
        
        try:
            # Check cache first
            cache_key = f"ph_{input_text}"
            cached_data = self.cache.get_raw_data(cache_key)
            if cached_data:
                return cached_data
            
            # Fetch from API
            data = self.product_hunt.search_product(input_text)
            
            # Cache it
            if data:
                self.cache.save_raw_data(cache_key, "producthunt", data, expiry_hours=24)
            
            return data
            
        except Exception as e:
            logger.error(f"Error gathering product data: {e}")
            return None
    
    def _gather_security_data(self, vendor: str, product: Optional[str] = None) -> Dict[str, Any]:
        """Gather CVE and KEV data"""
        
        cves = []
        kevs = []
        
        try:
            # Gather CVE data
            logger.info(f"Fetching CVEs for vendor: {vendor}")
            cache_key = f"cve_{vendor}_{product or 'all'}"
            cached_cves = self.cache.get_raw_data(cache_key)
            
            if cached_cves:
                cves = cached_cves
            else:
                cves = self.opencve.search_cves(vendor, product, limit=50)
                if cves:
                    self.cache.save_raw_data(cache_key, "cve", cves, expiry_hours=24)
            
            logger.info(f"Found {len(cves)} CVEs")
            
        except Exception as e:
            logger.error(f"Error gathering CVE data: {e}")
        
        try:
            # Gather KEV data
            logger.info(f"Fetching KEVs for vendor: {vendor}")
            cache_key = f"kev_{vendor}_{product or 'all'}"
            cached_kevs = self.cache.get_raw_data(cache_key)
            
            if cached_kevs:
                kevs = cached_kevs
            else:
                kevs = self.cisa_kev.search_kev(vendor, product)
                if kevs:
                    self.cache.save_raw_data(cache_key, "kev", kevs, expiry_hours=24)
            
            logger.info(f"Found {len(kevs)} KEVs")
            
        except Exception as e:
            logger.error(f"Error gathering KEV data: {e}")
        
        return {
            'cves': cves,
            'kevs': kevs
        }
    
    def _compile_assessment(self, entity_info: Dict, classification: Dict,
                          product_data: Optional[Dict], security_data: Dict,
                          vuln_analysis: Dict, trust_score: Dict,
                          alternatives: list) -> Dict[str, Any]:
        """Compile all information into final assessment"""
        
        assessment = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'input_query': entity_info.get('product_name')
            },
            'entity': {
                'product_name': entity_info.get('product_name'),
                'vendor': entity_info.get('vendor'),
                'url': entity_info.get('url'),
                'aliases': entity_info.get('aliases', []),
                'confidence': entity_info.get('confidence')
            },
            'classification': {
                'category': classification.get('primary_category'),
                'sub_category': classification.get('sub_category'),
                'additional_categories': classification.get('additional_categories', []),
                'use_cases': classification.get('use_cases', []),
                'deployment_model': classification.get('deployment_model')
            },
            'description': {
                'summary': product_data.get('description') if product_data else 'No description available',
                'tagline': product_data.get('tagline') if product_data else None,
                'topics': product_data.get('topics', []) if product_data else []
            },
            'security_posture': {
                'vulnerability_summary': {
                    'total_cves': len(security_data['cves']),
                    'total_kevs': len(security_data['kevs']),
                    'trend': vuln_analysis.get('trend'),
                    'exploitation_risk': vuln_analysis.get('exploitation_risk'),
                    'severity_distribution': vuln_analysis.get('severity_distribution', {}),
                    'critical_findings': vuln_analysis.get('critical_findings', []),
                    'key_concerns': vuln_analysis.get('key_concerns', []),
                    'positive_signals': vuln_analysis.get('positive_signals', [])
                },
                'recent_cves': security_data['cves'][:5],  # Top 5 recent/critical
                'kev_list': security_data['kevs'][:5]  # Top 5 KEVs
            },
            'trust_score': {
                'score': trust_score.get('score'),
                'risk_level': trust_score.get('risk_level'),
                'confidence': trust_score.get('confidence'),
                'rationale': trust_score.get('rationale'),
                'scoring_breakdown': trust_score.get('scoring_breakdown', {}),
                'key_factors': trust_score.get('key_factors', []),
                'data_limitations': trust_score.get('data_limitations', [])
            },
            'alternatives': alternatives,
            'recommendations': self._generate_recommendations(trust_score, vuln_analysis),
            'sources': self._compile_sources(product_data, security_data)
        }
        
        return assessment
    
    def _generate_recommendations(self, trust_score: Dict, vuln_analysis: Dict) -> list:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        score = trust_score.get('score', 50)
        risk_level = trust_score.get('risk_level', 'medium')
        
        if score < 40 or risk_level == 'critical':
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Do not approve without thorough security review',
                'reason': 'Low trust score indicates significant security concerns'
            })
        elif score < 60 or risk_level == 'high':
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Require vendor security assessment and remediation plan',
                'reason': 'Multiple security concerns identified'
            })
        else:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Proceed with standard security review',
                'reason': 'Acceptable security posture with manageable risks'
            })
        
        # KEV-specific recommendation
        if vuln_analysis.get('exploitation_risk') in ['high', 'critical']:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Verify all KEV vulnerabilities are patched',
                'reason': 'Known exploited vulnerabilities present'
            })
        
        return recommendations
    
    def _compile_sources(self, product_data: Optional[Dict], security_data: Dict) -> list:
        """Compile list of data sources with timestamps"""
        
        sources = []
        
        if product_data:
            sources.append({
                'name': 'ProductHunt',
                'type': 'Product Information',
                'timestamp': datetime.now().isoformat()
            })
        
        if security_data['cves']:
            sources.append({
                'name': 'OpenCVE',
                'type': 'CVE Data',
                'url': 'https://www.opencve.io',
                'count': len(security_data['cves']),
                'timestamp': datetime.now().isoformat()
            })
        
        if security_data['kevs']:
            sources.append({
                'name': 'CISA KEV Catalog',
                'type': 'Known Exploited Vulnerabilities',
                'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                'count': len(security_data['kevs']),
                'timestamp': datetime.now().isoformat()
            })
        
        return sources
    
    def get_assessment_history(self, limit: int = 100) -> list:
        """Get list of all cached assessments"""
        return self.cache.get_all_assessments(limit)
