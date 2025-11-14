# API Documentation

## REST API Endpoints

### Base URL
```
http://localhost:5000
```

---

## Endpoints

### 1. Health Check

Check the health status of the application.

**Endpoint:** `GET /api/health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-14T10:30:00.000Z",
  "components": {
    "assessor": true,
    "gemini_api": true,
    "producthunt_api": true
  }
}
```

**Status Codes:**
- `200 OK` - Service is healthy
- `503 Service Unavailable` - Service is unhealthy

---

### 2. Generate Assessment

Generate a comprehensive security assessment for a product.

**Endpoint:** `POST /assess`

**Request Headers:**
```
Content-Type: application/json
```

**Request Body:**
```json
{
  "input_text": "Slack",
  "use_cache": true
}
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| input_text | string | Yes | Product name, vendor, or URL |
| use_cache | boolean | No | Use cached results if available (default: true) |

**Response:**
```json
{
  "success": true,
  "assessment": {
    "metadata": {
      "timestamp": "2025-11-14T10:30:00.000Z",
      "version": "1.0",
      "input_query": "Slack"
    },
    "entity": {
      "product_name": "Slack",
      "vendor": "Salesforce",
      "url": "https://slack.com",
      "aliases": ["Slack Technologies"],
      "confidence": "high"
    },
    "classification": {
      "category": "SaaS Application",
      "sub_category": "Collaboration Platform",
      "additional_categories": ["Communication Tool"],
      "use_cases": ["Team communication", "Project collaboration"],
      "deployment_model": "SaaS"
    },
    "description": {
      "summary": "Team collaboration and messaging platform",
      "tagline": "Where work happens",
      "topics": ["Collaboration", "Communication", "Productivity"]
    },
    "security_posture": {
      "vulnerability_summary": {
        "total_cves": 15,
        "total_kevs": 0,
        "trend": "stable",
        "exploitation_risk": "low",
        "severity_distribution": {
          "critical": 0,
          "high": 2,
          "medium": 8,
          "low": 5
        },
        "critical_findings": [],
        "key_concerns": ["Legacy authentication vulnerabilities"],
        "positive_signals": ["Active security team", "Bug bounty program"]
      },
      "recent_cves": [...],
      "kev_list": [...]
    },
    "trust_score": {
      "score": 75,
      "risk_level": "low",
      "confidence": "high",
      "rationale": "Strong security posture with minimal exploitation risk...",
      "scoring_breakdown": {
        "vulnerability_history": {"score": 25, "reason": "..."},
        "kev_presence": {"score": 25, "reason": "..."},
        "vendor_reputation": {"score": 18, "reason": "..."},
        "product_maturity": {"score": 15, "reason": "..."},
        "security_practices": {"score": 8, "reason": "..."}
      },
      "key_factors": ["Established vendor", "No KEVs"],
      "data_limitations": ["Limited vendor security page data"]
    },
    "alternatives": [
      {
        "product_name": "Microsoft Teams",
        "vendor": "Microsoft",
        "rationale": "Enterprise-grade security with compliance certifications",
        "security_advantages": ["SOC2 certified", "Enterprise SSO"],
        "considerations": ["Different pricing model"]
      }
    ],
    "recommendations": [
      {
        "priority": "MEDIUM",
        "action": "Proceed with standard security review",
        "reason": "Acceptable security posture with manageable risks"
      }
    ],
    "sources": [
      {
        "name": "OpenCVE",
        "type": "CVE Data",
        "url": "https://www.opencve.io",
        "count": 15,
        "timestamp": "2025-11-14T10:30:00.000Z"
      }
    ],
    "_cached": false
  }
}
```

**Error Response:**
```json
{
  "error": "Assessment failed: Invalid API key"
}
```

**Status Codes:**
- `200 OK` - Assessment successful
- `400 Bad Request` - Invalid input
- `500 Internal Server Error` - Assessment failed
- `503 Service Unavailable` - Service not available

**Example cURL:**
```bash
curl -X POST http://localhost:5000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "input_text": "Slack",
    "use_cache": true
  }'
```

**Example Python:**
```python
import requests

response = requests.post(
    'http://localhost:5000/assess',
    json={
        'input_text': 'Slack',
        'use_cache': True
    }
)

if response.status_code == 200:
    data = response.json()
    assessment = data['assessment']
    print(f"Trust Score: {assessment['trust_score']['score']}/100")
```

---

## Assessment Object Schema

### Complete Schema

```json
{
  "metadata": {
    "timestamp": "ISO 8601 datetime",
    "version": "string",
    "input_query": "string"
  },
  "entity": {
    "product_name": "string",
    "vendor": "string",
    "url": "string | null",
    "aliases": ["string"],
    "confidence": "high | medium | low"
  },
  "classification": {
    "category": "string",
    "sub_category": "string",
    "additional_categories": ["string"],
    "use_cases": ["string"],
    "deployment_model": "SaaS | On-Premise | Hybrid | Mobile | Extension"
  },
  "description": {
    "summary": "string",
    "tagline": "string | null",
    "topics": ["string"]
  },
  "security_posture": {
    "vulnerability_summary": {
      "total_cves": "integer",
      "total_kevs": "integer",
      "trend": "improving | stable | concerning | insufficient_data",
      "exploitation_risk": "high | medium | low | unknown",
      "severity_distribution": {
        "critical": "integer",
        "high": "integer",
        "medium": "integer",
        "low": "integer"
      },
      "critical_findings": ["string"],
      "key_concerns": ["string"],
      "positive_signals": ["string"]
    },
    "recent_cves": [
      {
        "cve_id": "string",
        "summary": "string",
        "cvss_v3": "float",
        "severity": "string",
        "published_date": "string",
        "vendors": ["string"],
        "references": ["string"]
      }
    ],
    "kev_list": [
      {
        "cve_id": "string",
        "vendor_project": "string",
        "product": "string",
        "vulnerability_name": "string",
        "description": "string",
        "required_action": "string",
        "due_date": "string",
        "date_added": "string",
        "known_ransomware": "Known | Unknown"
      }
    ]
  },
  "trust_score": {
    "score": "integer (0-100)",
    "risk_level": "critical | high | medium | low",
    "confidence": "high | medium | low",
    "rationale": "string",
    "scoring_breakdown": {
      "vulnerability_history": {
        "score": "integer (0-30)",
        "reason": "string"
      },
      "kev_presence": {
        "score": "integer (0-25)",
        "reason": "string"
      },
      "vendor_reputation": {
        "score": "integer (0-20)",
        "reason": "string"
      },
      "product_maturity": {
        "score": "integer (0-15)",
        "reason": "string"
      },
      "security_practices": {
        "score": "integer (0-10)",
        "reason": "string"
      }
    },
    "key_factors": ["string"],
    "data_limitations": ["string"]
  },
  "alternatives": [
    {
      "product_name": "string",
      "vendor": "string",
      "rationale": "string",
      "security_advantages": ["string"],
      "considerations": ["string"]
    }
  ],
  "recommendations": [
    {
      "priority": "CRITICAL | HIGH | MEDIUM | LOW",
      "action": "string",
      "reason": "string"
    }
  ],
  "sources": [
    {
      "name": "string",
      "type": "string",
      "url": "string (optional)",
      "count": "integer (optional)",
      "timestamp": "ISO 8601 datetime"
    }
  ],
  "_cached": "boolean (optional)",
  "_cache_timestamp": "ISO 8601 datetime (optional)"
}
```

---

## Field Descriptions

### Trust Score Ranges
| Score | Risk Level | Interpretation |
|-------|-----------|----------------|
| 80-100 | Low | Excellent security posture |
| 60-79 | Medium | Good security, acceptable risk |
| 40-59 | High | Moderate concerns, requires review |
| 0-39 | Critical | Significant concerns, high risk |

### Vulnerability Trends
- `improving` - Fewer recent vulnerabilities, good patching
- `stable` - Consistent vulnerability rate
- `concerning` - Increasing vulnerabilities or poor patching
- `insufficient_data` - Not enough data to determine

### Exploitation Risk
- `high` - Active exploitation observed (KEVs present)
- `medium` - Vulnerabilities present but no active exploitation
- `low` - Minimal vulnerabilities, no exploitation
- `unknown` - Insufficient data

### Confidence Levels
- `high` - Strong data available, reliable assessment
- `medium` - Moderate data, reasonable confidence
- `low` - Limited data, use with caution

### Recommendation Priorities
- `CRITICAL` - Immediate action required
- `HIGH` - Prompt attention needed
- `MEDIUM` - Standard review process
- `LOW` - Informational

---

## Rate Limiting

Currently, there is no rate limiting implemented. For production use, consider:
- Implementing API key authentication
- Rate limiting per IP/key
- Request throttling

---

## Error Codes

| Status Code | Meaning | Common Causes |
|-------------|---------|---------------|
| 400 | Bad Request | Missing or invalid input_text |
| 500 | Internal Server Error | LLM error, API error, database error |
| 503 | Service Unavailable | Missing API keys, service not initialized |

---

## Caching Behavior

### Cache Keys
- Based on product name (case-insensitive)
- 24-hour expiry (configurable)

### Cache Headers
- `_cached`: `true` if result from cache
- `_cache_timestamp`: When cached result was generated

### Force Refresh
Set `use_cache: false` to bypass cache and generate fresh assessment

---

## Integration Examples

### JavaScript/Node.js
```javascript
const axios = require('axios');

async function assessProduct(productName) {
  const response = await axios.post('http://localhost:5000/assess', {
    input_text: productName,
    use_cache: true
  });
  
  const assessment = response.data.assessment;
  console.log(`Trust Score: ${assessment.trust_score.score}/100`);
  return assessment;
}

assessProduct('Slack');
```

### Python
```python
import requests

def assess_product(product_name):
    response = requests.post(
        'http://localhost:5000/assess',
        json={'input_text': product_name, 'use_cache': True}
    )
    response.raise_for_status()
    return response.json()['assessment']

assessment = assess_product('Slack')
print(f"Trust Score: {assessment['trust_score']['score']}/100")
```

### Bash/cURL
```bash
#!/bin/bash

PRODUCT="Slack"

curl -s -X POST http://localhost:5000/assess \
  -H "Content-Type: application/json" \
  -d "{\"input_text\": \"$PRODUCT\", \"use_cache\": true}" \
  | jq '.assessment.trust_score.score'
```

---

## Best Practices

### 1. Error Handling
Always check status codes and handle errors gracefully:
```python
try:
    response = requests.post(...)
    response.raise_for_status()
    assessment = response.json()['assessment']
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
```

### 2. Caching
- Use cache for repeat queries
- Force refresh for critical assessments
- Check `_cached` field to know data freshness

### 3. Timeout
Set reasonable timeouts:
```python
response = requests.post(..., timeout=120)  # 2 minutes
```

### 4. Pagination
Currently not implemented. All results returned in single response.

### 5. Concurrent Requests
- Compare multiple products in parallel
- Respect server resources
- Consider implementing client-side rate limiting

---

## Troubleshooting

### "Assessment failed"
- Check Gemini API key configuration
- Verify internet connectivity
- Check logs for specific error

### Slow Response
- First request for a product takes longer (30-60s)
- Cached results are instant
- Check network connection

### Empty CVE/KEV Data
- Normal for some vendors
- Try alternative vendor names
- Check OpenCVE availability

### Invalid JSON Response
- LLM occasionally produces malformed JSON
- System includes fallback handling
- Check logs for details

---

## Changelog

### Version 1.0 (Current)
- Initial release
- Basic assessment functionality
- OpenCVE and CISA KEV integration
- Gemini LLM analysis
- SQLite caching
- Flask web UI

---

## Future API Enhancements

### Planned Features
- [ ] Authentication with API keys
- [ ] Rate limiting
- [ ] Webhook notifications
- [ ] Batch assessments
- [ ] Historical tracking API
- [ ] Export formats (PDF, JSON, CSV)
- [ ] Real-time streaming responses
- [ ] GraphQL interface

---

## Support

For API issues or questions:
1. Check logs for error details
2. Verify API key configuration
3. Review example code
4. Check external API status (OpenCVE, CISA)

---

**API Version:** 1.0  
**Last Updated:** November 14, 2025
