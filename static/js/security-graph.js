/**
 * Security Ecosystem Graph Module
 * Creates an interactive knowledge graph showing relationships between
 * products, vendors, CVEs, alternatives, and data sources
 * 
 * Uses Vis.js Network for force-directed graph visualization
 */

let networkInstance = null;
let currentAssessment = null;

/**
 * Initialize and render the security ecosystem graph
 * @param {Object} assessment - The full assessment data
 */
function renderSecurityEcosystemGraph(assessment) {
    currentAssessment = assessment;
    
    const container = document.getElementById('securityGraph');
    if (!container) {
        console.error('Security graph container not found');
        return;
    }
    
    // Build graph data structure
    const { nodes, edges } = buildGraphData(assessment);
    
    // Configure graph appearance and physics
    const options = {
        nodes: {
            shape: 'dot',
            font: {
                size: 14,
                face: 'Arial',
                color: '#333'
            },
            borderWidth: 2,
            borderWidthSelected: 4,
            shadow: {
                enabled: true,
                color: 'rgba(0,0,0,0.1)',
                size: 5,
                x: 2,
                y: 2
            }
        },
        edges: {
            width: 2,
            color: {
                color: '#848484',
                highlight: '#667eea',
                hover: '#667eea'
            },
            smooth: {
                enabled: true,
                type: 'continuous',
                roundness: 0.5
            },
            arrows: {
                to: {
                    enabled: true,
                    scaleFactor: 0.5
                }
            },
            font: {
                size: 11,
                align: 'middle',
                color: '#666'
            }
        },
        physics: {
            enabled: false  // Disable physics for hierarchical layout
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            navigationButtons: true,
            keyboard: true,
            zoomView: true,
            dragView: true
        },
        layout: {
            hierarchical: {
                enabled: true,
                direction: 'LR',  // Left to Right (linear horizontal)
                sortMethod: 'directed',  // Directed graph
                levelSeparation: 250,  // Horizontal spacing between levels
                nodeSpacing: 150,  // Vertical spacing between nodes
                treeSpacing: 200,
                blockShifting: true,
                edgeMinimization: true,
                parentCentralization: true
            }
        }
    };
    
    // Create network
    const data = { nodes: nodes, edges: edges };
    networkInstance = new vis.Network(container, data, options);
    
    // Add event listeners
    setupGraphInteractions(networkInstance, assessment);
    
    // Log graph statistics
    console.log(`Security graph created: ${nodes.length} nodes, ${edges.length} edges`);
}

/**
 * Build nodes and edges from assessment data
 * @param {Object} assessment - Assessment data
 * @returns {Object} Object containing nodes and edges arrays
 */
function buildGraphData(assessment) {
    const nodes = [];
    const edges = [];
    
    const entity = assessment.entity;
    const security = assessment.security_posture;
    const alternatives = assessment.alternatives || [];
    const sources = assessment.sources || [];
    
    // 1. PRODUCT NODE (center, large)
    const productId = 'product';
    const productName = entity.product_name || entity.vendor || 'Unknown Product';
    nodes.push({
        id: productId,
        label: productName,
        title: `<b>${productName}</b><br>Trust Score: ${assessment.trust_score.total_score}/100<br>Category: ${assessment.classification.category}`,
        group: 'product',
        size: 40,
        level: 2,  // Center level
        color: {
            border: '#2980b9',
            background: '#3498db',
            highlight: {
                border: '#1f5f8b',
                background: '#5dade2'
            }
        },
        font: { size: 18, color: '#fff', bold: true },
        mass: 5  // Heavy node to stay central
    });
    
    // 2. VENDOR NODE
    if (entity.vendor) {
        const vendorId = 'vendor';
        nodes.push({
            id: vendorId,
            label: entity.vendor,
            title: `<b>Vendor:</b> ${entity.vendor}`,
            group: 'vendor',
            size: 30,
            level: 0,  // Leftmost - source
            color: {
                border: '#1e8449',
                background: '#27ae60',
                highlight: {
                    border: '#145a32',
                    background: '#52be80'
                }
            },
            font: { size: 16, color: '#fff' },
            mass: 3
        });
        
        // Edge: Vendor → Product (owns)
        edges.push({
            from: vendorId,
            to: productId,
            label: 'owns',
            width: 4,
            color: { color: '#27ae60' },
            arrows: { to: { scaleFactor: 0.8 } }
        });
    }
    
    // 3. CVE NODES (recent/critical vulnerabilities)
    const recentCVEs = security.recent_cves || [];
    const maxCVEs = 15; // Limit to prevent clutter
    
    recentCVEs.slice(0, maxCVEs).forEach((cve, index) => {
        const cveId = cve.cve_id;
        const severity = cve.severity || 'UNKNOWN';
        const cvssScore = cve.cvss_v3 || 'N/A';
        
        // Color based on severity
        const severityColors = {
            'CRITICAL': { border: '#7d0e0e', background: '#c0392b' },
            'HIGH': { border: '#a93226', background: '#e74c3c' },
            'MEDIUM': { border: '#b9770e', background: '#f39c12' },
            'LOW': { border: '#626567', background: '#95a5a6' },
            'UNKNOWN': { border: '#566573', background: '#7f8c8d' }
        };
        
        const colors = severityColors[severity] || severityColors['UNKNOWN'];
        
        nodes.push({
            id: cveId,
            label: cveId,
            title: `<b>${cveId}</b><br>Severity: ${severity}<br>CVSS: ${cvssScore}<br>${cve.summary ? cve.summary.substring(0, 100) + '...' : ''}`,
            group: 'cve',
            size: 12 + (severity === 'CRITICAL' ? 6 : severity === 'HIGH' ? 4 : 0),
            level: 3,  // Right of product - affected by
            color: {
                border: colors.border,
                background: colors.background,
                highlight: {
                    border: colors.border,
                    background: colors.background
                }
            },
            font: { size: 10, color: '#fff' },
            mass: 1
        });
        
        // Edge: CVE → Product (affects)
        edges.push({
            from: productId,
            to: cveId,
            label: 'affected by',
            width: severity === 'CRITICAL' ? 3 : severity === 'HIGH' ? 2 : 1,
            color: { color: colors.background },
            dashes: false
        });
    });
    
    // 4. KEV NODES (Known Exploited Vulnerabilities)
    const kevList = security.kev_list || [];
    
    kevList.forEach((kev, index) => {
        const kevId = `kev_${kev.cve_id}`;
        
        nodes.push({
            id: kevId,
            label: `⚠️ ${kev.cve_id}`,
            title: `<b>KNOWN EXPLOITED</b><br>${kev.cve_id}<br>${kev.vulnerability_name}<br>Added: ${kev.date_added}<br>Action Required: ${kev.required_action}`,
            group: 'kev',
            size: 18,
            level: 3,  // Same level as CVEs
            color: {
                border: '#641e16',
                background: '#8b0000',
                highlight: {
                    border: '#4a0e0e',
                    background: '#a30000'
                }
            },
            font: { size: 11, color: '#fff', bold: true },
            mass: 2,
            borderWidth: 3
        });
        
        // Edge: KEV → Product (actively exploited)
        edges.push({
            from: productId,
            to: kevId,
            label: 'exploited',
            width: 4,
            color: { color: '#8b0000' },
            dashes: [5, 5]  // Dashed line for urgency
        });
    });
    
    // 5. ALTERNATIVE PRODUCTS
    alternatives.forEach((alt, index) => {
        const altId = `alt_${index}`;
        const altName = alt.name || alt.product_name || 'Alternative';
        const altScore = alt.trust_score || 'N/A';
        
        nodes.push({
            id: altId,
            label: altName,
            title: `<b>Alternative:</b> ${altName}<br>Trust Score: ${altScore}<br>${alt.rationale || ''}`,
            group: 'alternative',
            size: 25,
            level: 4,  // Rightmost - alternatives
            color: {
                border: '#6c3483',
                background: '#9b59b6',
                highlight: {
                    border: '#512e5f',
                    background: '#af7ac5'
                }
            },
            font: { size: 14, color: '#fff' },
            mass: 2
        });
        
        // Edge: Product → Alternative (similar to)
        edges.push({
            from: productId,
            to: altId,
            label: 'alternative',
            width: 2,
            color: { color: '#9b59b6' },
            dashes: [10, 5],
            arrows: { to: { scaleFactor: 0.5 } }
        });
    });
    
    // 6. DATA SOURCE NODES
    sources.forEach((source, index) => {
        const sourceId = `source_${index}`;
        const sourceName = source.name || 'Data Source';
        
        nodes.push({
            id: sourceId,
            label: sourceName,
            title: `<b>Data Source:</b> ${sourceName}<br>Type: ${source.type || 'N/A'}<br>Records: ${source.count || 'N/A'}`,
            group: 'source',
            size: 15,
            level: 1,  // Between vendor and product
            color: {
                border: '#117a65',
                background: '#1abc9c',
                highlight: {
                    border: '#0e6655',
                    background: '#48c9b0'
                }
            },
            font: { size: 11, color: '#fff' },
            mass: 1,
            shape: 'square'  // Different shape for data sources
        });
        
        // Edge: Data Source → Product (provides data)
        edges.push({
            from: sourceId,
            to: productId,
            label: 'informs',
            width: 1,
            color: { color: '#1abc9c' },
            dashes: [2, 8],
            arrows: { to: { scaleFactor: 0.4 } }
        });
    });
    
    return { nodes, edges };
}

/**
 * Setup interactive behaviors for the graph
 * @param {vis.Network} network - Vis.js network instance
 * @param {Object} assessment - Assessment data
 */
function setupGraphInteractions(network, assessment) {
    // Click on node
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            handleNodeClick(nodeId, assessment);
        }
    });
    
    // Hover effect - highlight connected nodes
    network.on('hoverNode', function(params) {
        const nodeId = params.node;
        const connectedNodes = network.getConnectedNodes(nodeId);
        
        // Dim all nodes except connected ones
        const allNodes = network.body.data.nodes.get();
        allNodes.forEach(node => {
            if (node.id === nodeId || connectedNodes.includes(node.id)) {
                // Keep original opacity
                network.body.data.nodes.update({
                    id: node.id,
                    opacity: 1.0
                });
            } else {
                // Dim unrelated nodes
                network.body.data.nodes.update({
                    id: node.id,
                    opacity: 0.3
                });
            }
        });
    });
    
    // Reset on blur
    network.on('blurNode', function(params) {
        const allNodes = network.body.data.nodes.get();
        allNodes.forEach(node => {
            network.body.data.nodes.update({
                id: node.id,
                opacity: 1.0
            });
        });
    });
}

/**
 * Handle click on a graph node
 * @param {string} nodeId - ID of clicked node
 * @param {Object} assessment - Assessment data
 */
function handleNodeClick(nodeId, assessment) {
    console.log('Clicked node:', nodeId);
    
    // Handle CVE node clicks - open NVD link
    if (nodeId.startsWith('CVE-')) {
        const nvdUrl = `https://nvd.nist.gov/vuln/detail/${nodeId}`;
        window.open(nvdUrl, '_blank');
        return;
    }
    
    // Handle KEV node clicks - open CISA link
    if (nodeId.startsWith('kev_CVE-')) {
        const cveId = nodeId.replace('kev_', '');
        const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`;
        window.open(cisaUrl, '_blank');
        return;
    }
    
    // Handle product node - show detailed tooltip
    if (nodeId === 'product') {
        showNodeDetails('product', assessment);
    }
    
    // Handle alternative nodes - could trigger comparison
    if (nodeId.startsWith('alt_')) {
        console.log('Alternative product clicked - could trigger comparison');
    }
}

/**
 * Show detailed information about a node in a modal or expanded view
 * @param {string} nodeId - Node ID
 * @param {Object} assessment - Assessment data
 */
function showNodeDetails(nodeId, assessment) {
    // Could implement a modal popup with detailed information
    console.log('Showing details for:', nodeId);
    // For now, just log - could expand this feature
}

/**
 * Filter graph by CVE severity
 * @param {string} severity - 'all', 'critical', 'high', or 'critical_high'
 */
function filterGraphBySeverity(severity) {
    if (!networkInstance || !currentAssessment) {
        console.warn('Graph not initialized');
        return;
    }
    
    // Rebuild graph with filtered data
    const { nodes, edges } = buildGraphData(currentAssessment);
    
    if (severity !== 'all') {
        // Filter CVE nodes
        const filteredNodes = nodes.filter(node => {
            if (node.group !== 'cve') return true; // Keep non-CVE nodes
            
            const cve = currentAssessment.security_posture.recent_cves.find(c => c.cve_id === node.id);
            if (!cve) return false;
            
            if (severity === 'critical') {
                return cve.severity === 'CRITICAL';
            } else if (severity === 'high') {
                return cve.severity === 'HIGH';
            } else if (severity === 'critical_high') {
                return cve.severity === 'CRITICAL' || cve.severity === 'HIGH';
            }
            
            return true;
        });
        
        // Filter edges connected to removed CVE nodes
        const nodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredEdges = edges.filter(edge => 
            nodeIds.has(edge.from) && nodeIds.has(edge.to)
        );
        
        networkInstance.setData({ nodes: filteredNodes, edges: filteredEdges });
    } else {
        // Show all
        networkInstance.setData({ nodes, edges });
    }
    
    console.log(`Graph filtered by severity: ${severity}`);
}

/**
 * Re-center the graph view on the product node
 */
function centerGraphOnProduct() {
    if (!networkInstance) {
        console.warn('Graph not initialized');
        return;
    }
    
    networkInstance.focus('product', {
        scale: 1.0,
        animation: {
            duration: 1000,
            easingFunction: 'easeInOutQuad'
        }
    });
}

/**
 * Export graph as PNG image
 */
function exportGraphAsPNG() {
    if (!networkInstance) {
        console.warn('Graph not initialized');
        return;
    }
    
    const canvas = document.querySelector('#securityGraph canvas');
    if (canvas) {
        const link = document.createElement('a');
        link.download = 'security-ecosystem-graph.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
        console.log('Graph exported as PNG');
    } else {
        console.error('Canvas not found');
    }
}

/**
 * Toggle graph physics simulation
 */
function toggleGraphPhysics() {
    if (!networkInstance) return;
    
    const currentPhysics = networkInstance.physics.options.enabled;
    networkInstance.setOptions({ physics: { enabled: !currentPhysics } });
    console.log(`Graph physics ${!currentPhysics ? 'enabled' : 'disabled'}`);
}

/**
 * Get graph statistics
 * @returns {Object} Statistics about the graph
 */
function getGraphStats() {
    if (!networkInstance || !currentAssessment) return null;
    
    const nodes = networkInstance.body.data.nodes.get();
    const edges = networkInstance.body.data.edges.get();
    
    const nodesByType = nodes.reduce((acc, node) => {
        acc[node.group] = (acc[node.group] || 0) + 1;
        return acc;
    }, {});
    
    return {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        nodesByType: nodesByType,
        cveCount: nodesByType.cve || 0,
        kevCount: nodesByType.kev || 0,
        alternativeCount: nodesByType.alternative || 0,
        sourceCount: nodesByType.source || 0
    };
}

// Export functions for global access
window.renderSecurityEcosystemGraph = renderSecurityEcosystemGraph;
window.filterGraphBySeverity = filterGraphBySeverity;
window.centerGraphOnProduct = centerGraphOnProduct;
window.exportGraphAsPNG = exportGraphAsPNG;
window.toggleGraphPhysics = toggleGraphPhysics;
window.getGraphStats = getGraphStats;
