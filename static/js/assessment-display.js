/**
 * Assessment Display Module
 * Handles rendering of security assessment results
 */

/**
 * Display the complete assessment results
 * @param {Object} assessment - The assessment data object
 */
function displayAssessment(assessment) {
    const content = document.getElementById('resultsContent');
    
    const entity = assessment.entity;
    const classification = assessment.classification;
    const security = assessment.security_posture;
    const trustScore = assessment.trust_score;
    const securityPractices = assessment.security_practices;
    const incidents = assessment.incidents;
    const dataCompliance = assessment.data_compliance;
    const deploymentControls = assessment.deployment_controls;
    const alternatives = assessment.alternatives;
    const recommendations = assessment.recommendations;
    
    // Build trust score color
    const score = trustScore.total_score;
    let scoreColor = '#27ae60';
    if (score < 40) scoreColor = '#c33';
    else if (score < 60) scoreColor = '#e67e22';
    else if (score < 75) scoreColor = '#f39c12';
    
    let html = `
        ${renderEntityInfo(entity, classification)}
        ${renderTrustScore(trustScore, scoreColor)}
        ${renderSecurityPractices(securityPractices)}
        ${renderIncidents(incidents)}
        ${renderDataCompliance(dataCompliance)}
        ${renderDeploymentControls(deploymentControls)}
        ${renderSecurityPosture(security)}
        ${renderRecommendations(recommendations)}
        ${renderAlternatives(alternatives)}
        ${renderCitationVerification(assessment)}
        ${renderCitations(assessment)}
        ${renderMetadata(assessment)}
    `;
    
    content.innerHTML = html;
}

function renderEntityInfo(entity, classification) {
    return `
        <div style="margin-bottom: 2rem;">
            <h3>${entity.product_name}</h3>
            <p><strong>Vendor:</strong> ${entity.vendor}</p>
            ${entity.url ? `<p><strong>Website:</strong> <a href="${entity.url}" target="_blank">${entity.url}</a></p>` : ''}
            <p><strong>Category:</strong> ${classification.category} - ${classification.sub_category}</p>
        </div>
    `;
}

function renderTrustScore(trustScore, scoreColor) {
    const score = trustScore.total_score;
    
    const componentsHtml = Object.entries(trustScore.components).map(([key, comp]) => {
        const scorePercentage = (comp.score / comp.max_points * 100).toFixed(0);
        const barColor = scorePercentage > 70 ? '#27ae60' : scorePercentage > 50 ? '#f39c12' : '#c33';
        return `
            <div style="margin-bottom: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <strong style="text-transform: capitalize;">${key.replace(/_/g, ' ')}</strong>
                        <span style="background: #667eea; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem;">
                            ${comp.weight_percentage}% weight
                        </span>
                    </div>
                    <span style="font-size: 1.2rem; font-weight: bold; color: ${barColor};">
                        ${comp.score.toFixed(1)}/${comp.max_points} pts
                    </span>
                </div>
                <div style="background: #ddd; height: 20px; border-radius: 10px; overflow: hidden; margin-bottom: 0.5rem;">
                    <div style="background: ${barColor}; height: 100%; width: ${scorePercentage}%; transition: width 0.3s;"></div>
                </div>
                <div style="font-size: 0.9rem; color: #666;">
                    ${comp.explanation}
                </div>
            </div>
        `;
    }).join('');
    
    return `
        <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
            <h3>🎯 Trust Score (Rule-Based)</h3>
            <div style="font-size: 3rem; font-weight: bold; color: ${scoreColor}; margin: 1rem 0;">
                ${score}/100
            </div>
            <p><strong>Risk Level:</strong> <span class="badge ${trustScore.risk_level}">${trustScore.risk_level.toUpperCase()}</span></p>
            <p><strong>Confidence:</strong> ${trustScore.confidence}</p>
            
            <details open style="margin-top: 1.5rem;">
                <summary style="cursor: pointer; font-weight: bold; font-size: 1.1rem; margin-bottom: 1rem;">
                    📊 Scoring Breakdown - How is this calculated?
                </summary>
                <div style="background: white; padding: 1rem; border-radius: 6px;">
                    <p style="margin-bottom: 1rem; color: #666;">
                        This score uses <strong>transparent rule-based calculations</strong> - not AI-generated scores. 
                        Each component has fixed weights and deterministic formulas.
                    </p>
                    ${componentsHtml}
                    <div style="margin-top: 1rem; padding: 1rem; background: #e8f4f8; border-radius: 6px; border-left: 4px solid #3498db;">
                        <strong>Calculation Method:</strong> ${trustScore.calculation_method}
                    </div>
                </div>
            </details>
        </div>
    `;
}

function renderSecurityPractices(securityPractices) {
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🔒 Security Practices</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <p><strong>Overall Rating:</strong> <span class="badge">${securityPractices.rating.toUpperCase()}</span></p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0;">
                    <div>
                        <strong>Bug Bounty:</strong> ${securityPractices.bug_bounty === true ? '✅ Yes' : securityPractices.bug_bounty === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Disclosure Policy:</strong> ${securityPractices.disclosure_policy === true ? '✅ Yes' : securityPractices.disclosure_policy === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Security Team:</strong> ${securityPractices.security_team_visible === true ? '✅ Visible' : securityPractices.security_team_visible === false ? '❌ Not Visible' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Patch Cadence:</strong> ${securityPractices.patch_cadence}
                    </div>
                </div>
                <p style="margin-top: 1rem;">${securityPractices.summary}</p>
            </div>
        </div>
    `;
}

function renderIncidents(incidents) {
    if (incidents.count === 0 && incidents.severity === 'none') {
        return '';
    }
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>⚠️ Security Incidents & Abuse Signals</h3>
            <div style="background: ${incidents.severity === 'high' || incidents.severity === 'critical' ? '#fee' : '#fef8e7'}; 
                        padding: 1.5rem; border-radius: 8px; border-left: 4px solid ${incidents.severity === 'high' || incidents.severity === 'critical' ? '#c33' : '#f39c12'};">
                <p><strong>Incident Count:</strong> ${incidents.count}</p>
                <p><strong>Severity:</strong> <span class="badge ${incidents.severity}">${incidents.severity.toUpperCase()}</span></p>
                <p><strong>Rating:</strong> ${incidents.rating.toUpperCase()}</p>
                <p style="margin-top: 1rem;">${incidents.summary}</p>
                ${incidents.incidents && incidents.incidents.length > 0 ? `
                    <details style="margin-top: 1rem;">
                        <summary style="cursor: pointer; font-weight: bold;">View Incident Details</summary>
                        <ul style="margin-top: 0.5rem;">
                            ${incidents.incidents.map(inc => `<li>${JSON.stringify(inc)}</li>`).join('')}
                        </ul>
                    </details>
                ` : ''}
            </div>
        </div>
    `;
}

function renderDataCompliance(dataCompliance) {
    return `
        <div style="margin-bottom: 2rem;">
            <h3>📋 Data Handling & Compliance</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <p><strong>Compliance Status:</strong> <span class="badge ${dataCompliance.status === 'compliant' ? 'low' : dataCompliance.status === 'partial' ? 'medium' : 'high'}">
                    ${dataCompliance.status.toUpperCase()}
                </span></p>
                <p><strong>GDPR Compliant:</strong> ${dataCompliance.gdpr_compliant === true ? '✅ Yes' : dataCompliance.gdpr_compliant === false ? '❌ No' : '❓ Unknown'}</p>
                <p><strong>Privacy Rating:</strong> ${dataCompliance.privacy_rating.toUpperCase()}</p>
                ${dataCompliance.certifications && dataCompliance.certifications.length > 0 ? `
                    <p><strong>Certifications:</strong> ${dataCompliance.certifications.join(', ')}</p>
                ` : ''}
                <p><strong>Data Residency:</strong> ${dataCompliance.data_residency}</p>
                <p style="margin-top: 1rem;">${dataCompliance.summary}</p>
            </div>
        </div>
    `;
}

function renderDeploymentControls(deploymentControls) {
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🛠️ Deployment & Admin Controls</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                <p><strong>Control Rating:</strong> <span class="badge">${deploymentControls.control_rating.toUpperCase()}</span></p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0;">
                    <div>
                        <strong>SSO Support:</strong> ${deploymentControls.sso_support === true ? '✅ Yes' : deploymentControls.sso_support === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>MFA Support:</strong> ${deploymentControls.mfa_support === true ? '✅ Yes' : deploymentControls.mfa_support === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>RBAC Available:</strong> ${deploymentControls.rbac_available === true ? '✅ Yes' : deploymentControls.rbac_available === false ? '❌ No' : '❓ Unknown'}
                    </div>
                    <div>
                        <strong>Audit Logging:</strong> ${deploymentControls.audit_logging === true ? '✅ Yes' : deploymentControls.audit_logging === false ? '❌ No' : '❓ Unknown'}
                    </div>
                </div>
                ${deploymentControls.key_features && deploymentControls.key_features.length > 0 ? `
                    <div style="margin-top: 1rem;">
                        <strong>Key Features:</strong>
                        <ul>
                            ${deploymentControls.key_features.map(f => `<li>${f}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${deploymentControls.limitations && deploymentControls.limitations.length > 0 ? `
                    <div style="margin-top: 1rem;">
                        <strong>Limitations:</strong>
                        <ul>
                            ${deploymentControls.limitations.map(l => `<li>${l}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                <p style="margin-top: 1rem;">${deploymentControls.summary}</p>
            </div>
        </div>
    `;
}

function renderSecurityPosture(security) {
    return `
        <div style="margin-bottom: 2rem;">
            <h3>Security Posture Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #667eea;">${security.vulnerability_summary.total_cves}</div>
                    <div>Total CVEs</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 2rem; font-weight: bold; color: #c33;">${security.vulnerability_summary.total_kevs}</div>
                    <div>Known Exploited</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">${security.vulnerability_summary.trend}</div>
                    <div>Trend</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #e67e22;">${security.vulnerability_summary.exploitation_risk}</div>
                    <div>Exploitation Risk</div>
                </div>
            </div>
            
            ${security.vulnerability_summary.critical_findings.length > 0 ? `
                <div style="background: #fee; padding: 1rem; border-radius: 8px; border-left: 4px solid #c33; margin-top: 1rem;">
                    <h4>⚠️ Critical Findings</h4>
                    <ul>
                        ${security.vulnerability_summary.critical_findings.map(f => `<li>${f}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${security.vulnerability_summary.key_concerns.length > 0 ? `
                <div style="margin-top: 1rem;">
                    <h4>Key Concerns</h4>
                    <ul>
                        ${security.vulnerability_summary.key_concerns.map(c => `<li>${c}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

function renderRecommendations(recommendations) {
    if (!recommendations || recommendations.length === 0) {
        return '';
    }
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>Recommendations</h3>
            ${recommendations.map(rec => `
                <div style="background: ${rec.priority === 'CRITICAL' ? '#fee' : rec.priority === 'HIGH' ? '#fed' : '#ffc'}; 
                            padding: 1rem; border-radius: 8px; margin-bottom: 1rem; 
                            border-left: 4px solid ${rec.priority === 'CRITICAL' ? '#c33' : rec.priority === 'HIGH' ? '#e67e22' : '#f39c12'};">
                    <strong>${rec.priority}:</strong> ${rec.action}
                    <br><small>${rec.reason}</small>
                </div>
            `).join('')}
        </div>
    `;
}

function renderAlternatives(alternatives) {
    if (!alternatives || alternatives.length === 0) {
        return '';
    }
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>Safer Alternatives</h3>
            ${alternatives.map(alt => `
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                    <h4>${alt.product_name} (${alt.vendor})</h4>
                    <p>${alt.rationale}</p>
                    ${alt.security_advantages.length > 0 ? `
                        <ul>
                            ${alt.security_advantages.map(adv => `<li>${adv}</li>`).join('')}
                        </ul>
                    ` : ''}
                </div>
            `).join('')}
        </div>
    `;
}

function renderCitationVerification(assessment) {
    // Check if multi-agent analysis was used with citation verification
    if (!assessment.citation_summary && !assessment._multi_agent_metadata) {
        return '';
    }
    
    const citationSummary = assessment.citation_summary || {};
    const multiAgentMeta = assessment._multi_agent_metadata || {};
    
    // If no citation data, return empty
    if (!citationSummary.total_citations && !multiAgentMeta.verification_applied) {
        return '';
    }
    
    const totalCitations = citationSummary.total_citations || 0;
    const verifiedUrls = citationSummary.verified_urls || 0;
    const brokenUrls = citationSummary.broken_urls || 0;
    const verificationRate = citationSummary.url_verification_rate || '0%';
    
    // Determine verification quality
    let verificationQuality = 'unknown';
    let qualityColor = '#95a5a6';
    const rate = parseFloat(verificationRate);
    
    if (rate >= 90) {
        verificationQuality = 'excellent';
        qualityColor = '#27ae60';
    } else if (rate >= 70) {
        verificationQuality = 'good';
        qualityColor = '#2ecc71';
    } else if (rate >= 50) {
        verificationQuality = 'moderate';
        qualityColor = '#f39c12';
    } else if (rate > 0) {
        verificationQuality = 'poor';
        qualityColor = '#e67e22';
    } else {
        verificationQuality = 'failed';
        qualityColor = '#c0392b';
    }
    
    // Count verified, partially verified, and unverified findings
    const verifiedFindings = (assessment.verified_findings || []).length;
    const partialFindings = (assessment.partially_verified_findings || []).length;
    const unverifiedClaims = (assessment.unverified_claims || []).length;
    const totalFindings = verifiedFindings + partialFindings + unverifiedClaims;
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>🔍 Citation Verification</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                ${multiAgentMeta.verification_applied ? `
                    <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 6px; border-left: 4px solid #667eea;">
                        <strong>✓ Multi-Agent Verification Completed</strong>
                        <div style="margin-top: 0.5rem; font-size: 0.9rem; color: #666;">
                            Pipeline: ${multiAgentMeta.pipeline || 'unknown'}
                        </div>
                    </div>
                ` : ''}
                
                ${totalCitations > 0 ? `
                    <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 6px; border-left: 4px solid ${qualityColor};">
                        <strong>📊 URL Verification Summary:</strong>
                        <div style="margin-top: 1rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                            <div>
                                <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">${totalCitations}</div>
                                <div style="font-size: 0.85rem; color: #666;">Total Citations</div>
                            </div>
                            <div>
                                <div style="font-size: 1.5rem; font-weight: bold; color: #27ae60;">${verifiedUrls}</div>
                                <div style="font-size: 0.85rem; color: #666;">Accessible URLs ✓</div>
                            </div>
                            <div>
                                <div style="font-size: 1.5rem; font-weight: bold; color: #c0392b;">${brokenUrls}</div>
                                <div style="font-size: 0.85rem; color: #666;">Broken URLs ✗</div>
                            </div>
                            <div>
                                <div style="font-size: 1.5rem; font-weight: bold; color: ${qualityColor};">${verificationRate}</div>
                                <div style="font-size: 0.85rem; color: #666;">Verification Rate</div>
                            </div>
                        </div>
                        <div style="margin-top: 1rem; padding: 0.75rem; background: #f8f9fa; border-radius: 4px;">
                            <strong>Verification Quality:</strong>
                            <span class="badge" style="background: ${qualityColor}; color: white; padding: 0.3rem 0.6rem; border-radius: 4px; text-transform: uppercase; margin-left: 0.5rem;">
                                ${verificationQuality}
                            </span>
                        </div>
                    </div>
                ` : ''}
                
                ${totalFindings > 0 ? `
                    <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 6px;">
                        <strong>📋 Findings Classification:</strong>
                        <div style="margin-top: 1rem;">
                            ${verifiedFindings > 0 ? `
                                <div style="margin-bottom: 0.75rem; padding: 0.75rem; background: #d5f4e6; border-radius: 4px; border-left: 3px solid #27ae60;">
                                    <strong style="color: #27ae60;">✓ Fully Verified Findings:</strong>
                                    <span style="font-size: 1.2rem; font-weight: bold; margin-left: 0.5rem;">${verifiedFindings}</span>
                                    <div style="font-size: 0.85rem; color: #666; margin-top: 0.25rem;">All citations have accessible URLs</div>
                                </div>
                            ` : ''}
                            ${partialFindings > 0 ? `
                                <div style="margin-bottom: 0.75rem; padding: 0.75rem; background: #fef5e7; border-radius: 4px; border-left: 3px solid #f39c12;">
                                    <strong style="color: #f39c12;">⚠ Partially Verified Findings:</strong>
                                    <span style="font-size: 1.2rem; font-weight: bold; margin-left: 0.5rem;">${partialFindings}</span>
                                    <div style="font-size: 0.85rem; color: #666; margin-top: 0.25rem;">Some citations have broken or inaccessible URLs</div>
                                </div>
                            ` : ''}
                            ${unverifiedClaims > 0 ? `
                                <div style="margin-bottom: 0.75rem; padding: 0.75rem; background: #fadbd8; border-radius: 4px; border-left: 3px solid #c0392b;">
                                    <strong style="color: #c0392b;">✗ Unverified Claims:</strong>
                                    <span style="font-size: 1.2rem; font-weight: bold; margin-left: 0.5rem;">${unverifiedClaims}</span>
                                    <div style="font-size: 0.85rem; color: #666; margin-top: 0.25rem;">No accessible citations found - excluded from final report</div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                ` : ''}
                
                ${(assessment.broken_urls || []).length > 0 ? `
                    <details style="margin-top: 1rem;">
                        <summary style="cursor: pointer; font-weight: bold; color: #c0392b;">
                            ⚠️ Broken URLs Detected (${assessment.broken_urls.length})
                        </summary>
                        <div style="margin-top: 0.75rem; padding: 1rem; background: white; border-radius: 6px;">
                            ${assessment.broken_urls.map((url, idx) => `
                                <div style="margin-bottom: 0.5rem; padding: 0.5rem; background: #fadbd8; border-radius: 4px; font-size: 0.9rem; word-break: break-all;">
                                    ${idx + 1}. ${url}
                                </div>
                            `).join('')}
                        </div>
                    </details>
                ` : ''}
            </div>
        </div>
    `;
}

function renderCitations(assessment) {
    if (!assessment.citations || assessment.citations.length === 0) {
        return '';
    }
    
    const evidenceSummaryHtml = assessment.evidence_summary ? `
        <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 6px; border-left: 4px solid ${assessment.evidence_summary.total_evidence > 0 ? '#667eea' : '#f39c12'};">
            <strong>📊 Evidence Summary:</strong>
            <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                <div>
                    <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">${assessment.evidence_summary.total_evidence || 0}</div>
                    <div style="font-size: 0.85rem; color: #666;">Total Evidence Items</div>
                </div>
                <div>
                    <div style="font-size: 1.5rem; font-weight: bold; color: #3498db;">${assessment.evidence_summary.vendor_stated || 0}</div>
                    <div style="font-size: 0.85rem; color: #666;">Vendor Claims (${(assessment.evidence_summary.vendor_percentage || 0).toFixed(1)}%)</div>
                </div>
                <div>
                    <div style="font-size: 1.5rem; font-weight: bold; color: #27ae60;">${assessment.evidence_summary.independent_verification || 0}</div>
                    <div style="font-size: 0.85rem; color: #666;">Independent Sources (${(assessment.evidence_summary.independent_percentage || 0).toFixed(1)}%)</div>
                </div>
                ${(assessment.evidence_summary.mixed_sources || 0) > 0 ? `
                <div>
                    <div style="font-size: 1.5rem; font-weight: bold; color: #f39c12;">${assessment.evidence_summary.mixed_sources}</div>
                    <div style="font-size: 0.85rem; color: #666;">Mixed Sources</div>
                </div>
                ` : ''}
            </div>
            <div style="margin-top: 0.5rem; padding: 0.5rem; background: #f8f9fa; border-radius: 4px;">
                <strong>Evidence Quality:</strong> 
                <span class="badge" style="text-transform: uppercase;">${assessment.evidence_summary.evidence_quality || 'unknown'}</span>
                ${assessment.evidence_summary.total_evidence === 0 ? `
                    <span style="margin-left: 1rem; color: #e67e22;">⚠️ No evidence tracked - assessment based on public data only</span>
                ` : ''}
            </div>
        </div>
    ` : `
        <div style="margin-bottom: 1rem; padding: 1rem; background: #fef8e7; border-radius: 6px; border-left: 4px solid #f39c12;">
            <strong>⚠️ Limited Evidence:</strong> No evidence summary available for this assessment.
        </div>
    `;
    
    const citationsHtml = assessment.citations.map((cite, idx) => {
        const sourceType = cite.source_type || 'unknown';
        const color = sourceType === 'independent' ? '#27ae60' : sourceType === 'vendor' ? '#3498db' : '#f39c12';
        
        // Check for URL verification status
        const urlStatus = cite.url_status || '';
        let statusIcon = '';
        let statusColor = '';
        
        if (urlStatus === '✓' || urlStatus === 'accessible') {
            statusIcon = '✓';
            statusColor = '#27ae60';
        } else if (urlStatus === '⚠' || urlStatus === 'redirect') {
            statusIcon = '⚠';
            statusColor = '#f39c12';
        } else if (urlStatus === '✗' || urlStatus === 'broken') {
            statusIcon = '✗';
            statusColor = '#c0392b';
        }
        
        return `
            <div style="background: white; padding: 1rem; border-radius: 6px; margin-bottom: 0.5rem; border-left: 4px solid ${color};">
                <div style="font-size: 0.85rem; color: #666; margin-bottom: 0.25rem;">
                    <strong>[${idx + 1}]</strong>
                    <span class="badge" style="background: ${color}; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem;">
                        ${sourceType.toUpperCase()}
                    </span>
                    ${statusIcon ? `
                        <span style="background: ${statusColor}; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-left: 0.5rem; font-weight: bold;">
                            ${statusIcon}
                        </span>
                    ` : ''}
                </div>
                <div style="font-weight: bold; margin-bottom: 0.25rem;">${cite.source || 'Unknown Source'}</div>
                ${cite.content ? `<div style="font-size: 0.9rem; margin-bottom: 0.5rem;">${cite.content}</div>` : ''}
                ${cite.quote ? `<div style="font-size: 0.9rem; margin-bottom: 0.5rem; font-style: italic; color: #555; border-left: 3px solid #ddd; padding-left: 0.75rem;">"${cite.quote}"</div>` : ''}
                ${cite.url ? `
                    <div style="font-size: 0.85rem;">
                        <a href="${cite.url}" target="_blank" style="color: #667eea;">🔗 Source Link</a>
                        ${statusIcon === '✗' ? `<span style="color: #c0392b; margin-left: 0.5rem; font-size: 0.8rem;">(URL not accessible)</span>` : ''}
                        ${statusIcon === '⚠' ? `<span style="color: #f39c12; margin-left: 0.5rem; font-size: 0.8rem;">(URL redirects)</span>` : ''}
                        ${statusIcon === '✓' ? `<span style="color: #27ae60; margin-left: 0.5rem; font-size: 0.8rem;">(URL verified)</span>` : ''}
                    </div>
                ` : ''}
                ${cite.accessed ? `<div style="font-size: 0.8rem; color: #999; margin-top: 0.25rem;">Accessed: ${cite.accessed}</div>` : ''}
            </div>
        `;
    }).join('');
    
    return `
        <div style="margin-bottom: 2rem;">
            <h3>📚 Evidence & Citations</h3>
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px;">
                ${evidenceSummaryHtml}
                <details>
                    <summary style="cursor: pointer; font-weight: bold; margin-bottom: 0.5rem;">
                        View All Citations (${assessment.citations.length})
                    </summary>
                    <div style="margin-top: 1rem;">
                        ${citationsHtml || '<div style="padding: 1rem; color: #666; text-align: center;">No citations available</div>'}
                    </div>
                </details>
            </div>
        </div>
    `;
}

function renderMetadata(assessment) {
    return `
        <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; font-size: 0.9rem; color: #666;">
            <strong>Sources:</strong>
            ${assessment.sources.map(s => s.name).join(', ')}
            <br>
            <strong>Generated:</strong> ${new Date(assessment.metadata.timestamp).toLocaleString()}
            ${assessment._cached ? `<br><strong>⚡ From Cache:</strong> ${new Date(assessment._cache_timestamp).toLocaleString()}` : ''}
            ${assessment.metadata.evidence_hash ? `<br><strong>Evidence Hash:</strong> <code style="font-size: 0.8rem;">${assessment.metadata.evidence_hash.substring(0, 16)}...</code>` : ''}
        </div>
    `;
}
