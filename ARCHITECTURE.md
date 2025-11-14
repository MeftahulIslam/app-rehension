# Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │   Home Page  │  │   Compare    │  │   History    │        │
│  │  Assessment  │  │    View      │  │    View      │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
│                    Flask Web UI (app.py)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ASSESSMENT ENGINE                            │
│                     (assessor.py)                               │
│                                                                 │
│  Step 1: Entity Resolution                                     │
│  Step 2: Data Gathering                                        │
│  Step 3: Vulnerability Analysis                                │
│  Step 4: Trust Score Calculation                               │
│  Step 5: Alternative Suggestions                               │
│  Step 6: Report Compilation                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │   LLM Layer  │ │ Data Sources │ │ Cache Layer  │
    │   (Gemini)   │ │   (APIs)     │ │  (SQLite)    │
    └──────────────┘ └──────────────┘ └──────────────┘
            │                 │               │
            │                 │               │
            ▼                 ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ Entity       │ │ ProductHunt  │ │ Assessments  │
    │ Resolution   │ │ OpenCVE      │ │ Raw Data     │
    │ Classification│ │ CISA KEV     │ │ Timestamps   │
    │ Analysis     │ │              │ │              │
    │ Scoring      │ │              │ │              │
    └──────────────┘ └──────────────┘ └──────────────┘
```

## Data Flow

```
User Input (Product Name/URL)
        │
        ▼
┌───────────────────┐
│ Entity Resolution │  ← Gemini LLM
│ (Product, Vendor) │
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Data Gathering    │
├───────────────────┤
│ • ProductHunt API │ → Product info, metadata
│ • OpenCVE API     │ → CVE vulnerabilities
│ • CISA KEV        │ → Known exploited vulns
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ LLM Analysis      │  ← Gemini LLM
├───────────────────┤
│ • Classification  │ → Software taxonomy
│ • Vuln Analysis   │ → Risk assessment
│ • Trust Scoring   │ → 0-100 score
│ • Alternatives    │ → Safer options
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Assessment Report │
├───────────────────┤
│ • Entity Info     │
│ • Security Posture│
│ • Trust Score     │
│ • Recommendations │
│ • Alternatives    │
│ • Sources         │
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Cache in SQLite   │ → 24-hour cache
└───────────────────┘
        │
        ▼
    Display to User
```

## Component Details

### 1. Flask Web Application (app.py)
- **Routes**: /, /assess, /history, /compare, /api/health
- **Templates**: Base, Index, History, Compare, Error
- **Static Assets**: Embedded CSS in templates
- **API Endpoints**: RESTful JSON API

### 2. Assessment Engine (assessor.py)
- **SecurityAssessor Class**: Main orchestrator
- **Methods**:
  - `assess_product()`: Main workflow
  - `_gather_product_data()`: Fetch product info
  - `_gather_security_data()`: Fetch CVE/KEV
  - `_compile_assessment()`: Build final report

### 3. LLM Analyzer (llm_analyzer.py)
- **GeminiAnalyzer Class**: Gemini integration
- **Methods**:
  - `resolve_entity()`: Extract product/vendor
  - `classify_software()`: Categorize product
  - `analyze_vulnerabilities()`: Assess CVE/KEV data
  - `calculate_trust_score()`: Compute 0-100 score
  - `suggest_alternatives()`: Find safer options

### 4. Data Sources (data_sources.py)
- **ProductHuntAPI**: Product information
- **OpenCVEAPI**: CVE vulnerability data
- **CISAKEVAPI**: Known exploited vulnerabilities
- **WebSourceFetcher**: Additional web scraping

### 5. Database Layer (database.py)
- **AssessmentCache Class**: SQLite management
- **Tables**:
  - `assessments`: Full assessment reports
  - `data_cache`: Raw API responses
- **Features**: Expiry tracking, timestamps, indexing

### 6. Configuration (config.py)
- **Config Class**: Centralized settings
- **Environment Variables**: API keys, paths, settings
- **Defaults**: Model settings, cache duration

## Security Features

### Hallucination Prevention
1. **Low Temperature** (0.1): Consistent, factual outputs
2. **Structured JSON**: Parseable, validatable responses
3. **Source Attribution**: Every claim cited
4. **Confidence Levels**: Uncertainty indication
5. **Evidence Grounding**: Claims tied to data
6. **Insufficient Data Handling**: Clear when lacking info

### Data Validation
1. **Input Sanitization**: User inputs validated
2. **API Response Validation**: Check status codes
3. **JSON Schema Validation**: LLM outputs verified
4. **Error Handling**: Graceful degradation

### Privacy & Security
1. **No PII Storage**: Only public product data
2. **API Key Management**: Environment variables
3. **Read-Only Operations**: No data modification
4. **Local Caching**: Reproducibility without re-fetching

## Caching Strategy

### Assessment Cache
- **Duration**: 24 hours (configurable)
- **Key**: Product name
- **Content**: Full assessment JSON
- **Benefit**: Instant results for repeat queries

### Raw Data Cache
- **Duration**: 24 hours (configurable)
- **Keys**: vendor_product combinations
- **Content**: API responses
- **Benefit**: Reduced API calls, faster processing

### Cache Invalidation
- **Time-based**: Automatic expiry
- **Manual**: `use_cache=false` parameter
- **Cleanup**: Periodic removal of expired entries

## Scalability Considerations

### Current Design (Single Instance)
- SQLite for local caching
- Synchronous processing
- Single-threaded Flask

### Future Enhancements
- PostgreSQL for multi-instance caching
- Async processing with Celery
- Redis for distributed caching
- Load balancing with Gunicorn
- Docker containerization
- Kubernetes orchestration

## API Integration Details

### ProductHunt API
- **Type**: GraphQL
- **Auth**: Bearer token
- **Rate Limit**: Reasonable use
- **Data**: Product metadata, votes, topics

### OpenCVE API
- **Type**: REST
- **Auth**: None (public)
- **Rate Limit**: Fair use policy
- **Data**: CVE summaries, CVSS scores

### CISA KEV
- **Type**: JSON feed
- **Auth**: None (public)
- **Update**: Daily
- **Data**: Known exploited vulnerabilities

### Gemini API
- **Type**: REST
- **Auth**: API key
- **Rate Limit**: Based on plan
- **Model**: gemini-1.5-pro

## Error Handling

### Network Errors
- Retry logic with exponential backoff
- Fallback to cached data
- User-friendly error messages

### API Errors
- Status code checking
- Timeout handling
- Partial data processing

### LLM Errors
- JSON parsing failures
- Malformed responses
- Fallback to default values

### Database Errors
- Connection handling
- Transaction rollback
- Auto-creation of tables

## Performance Metrics

### Typical Assessment Timeline
1. **Cache Hit**: < 1 second
2. **Cache Miss**:
   - Entity Resolution: 3-5 seconds
   - Data Gathering: 10-15 seconds
   - Analysis: 15-20 seconds
   - Report Generation: 2-3 seconds
   - **Total**: 30-45 seconds

### Resource Usage
- **Memory**: ~100-200 MB
- **Disk**: ~10 MB (database)
- **CPU**: Minimal (mostly I/O bound)
- **Network**: ~1-5 MB per assessment

## Monitoring & Observability

### Logging
- **Level**: INFO (configurable)
- **Format**: Timestamp, component, level, message
- **Location**: Console (stdout)

### Health Check
- **Endpoint**: `/api/health`
- **Checks**: Assessor initialization, API keys
- **Response**: JSON status

### Metrics (Future)
- Assessment duration
- Cache hit rate
- API call counts
- Error rates

---

## Quick Reference

### File Structure
```
app.py              - Flask web application
assessor.py         - Assessment orchestration
llm_analyzer.py     - Gemini LLM integration
data_sources.py     - API clients
database.py         - SQLite caching
config.py           - Configuration
templates/          - HTML templates
data/               - SQLite database
```

### Key Classes
- `SecurityAssessor` - Main assessment engine
- `GeminiAnalyzer` - LLM integration
- `AssessmentCache` - Database operations
- `ProductHuntAPI` - ProductHunt client
- `OpenCVEAPI` - OpenCVE client
- `CISAKEVAPI` - CISA KEV client

### Environment Variables
- `GEMINI_API_KEY` - Required
- `PRODUCTHUNT_API_KEY` - Optional
- `DATABASE_PATH` - Optional
- `CACHE_EXPIRY_HOURS` - Optional

---

**Built with modularity, extensibility, and reliability in mind.**
