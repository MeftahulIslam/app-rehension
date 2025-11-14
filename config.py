import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    
    # API Keys
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    PRODUCTHUNT_API_KEY = os.getenv('PRODUCTHUNT_API_KEY')
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Database
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'data/assessments.db')
    
    # API Endpoints
    OPENCVE_API_BASE = "https://www.opencve.io/api"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    PRODUCTHUNT_API_BASE = "https://api.producthunt.com/v2/api/graphql"
    
    # LLM Settings
    GEMINI_MODEL = "gemini-1.5-pro"
    GEMINI_TEMPERATURE = 0.1  # Low temperature for consistent, factual responses
    GEMINI_MAX_TOKENS = 4096
    
    # Cache settings
    CACHE_EXPIRY_HOURS = 24
