/**
 * Form Handler Module
 * Handles form submission and assessment initiation
 */

document.addEventListener('DOMContentLoaded', function() {
    const assessmentForm = document.getElementById('assessmentForm');
    
    if (assessmentForm) {
        assessmentForm.addEventListener('submit', handleFormSubmit);
    }
});

/**
 * Handle assessment form submission
 * @param {Event} e - Form submit event
 */
async function handleFormSubmit(e) {
    e.preventDefault();
    
    const inputText = document.getElementById('input_text').value.trim();
    const useCache = document.getElementById('use_cache').checked;
    const submitBtn = document.getElementById('submitBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const errorMsg = document.getElementById('errorMsg');
    const progressMessage = document.getElementById('progressMessage');
    const multiAgentProgress = document.getElementById('multiAgentProgress');
    
    // Clear previous results
    results.style.display = 'none';
    errorMsg.innerHTML = '';
    
    // Reset progress stages
    resetProgressStages();
    
    // Show loading
    loading.classList.add('active');
    submitBtn.disabled = true;
    progressMessage.textContent = 'Starting assessment...';
    
    // Generate session ID
    const sessionId = Date.now().toString();
    
    try {
        // Start assessment
        const response = await fetch('/assess', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                input_text: inputText,
                use_cache: useCache,
                session_id: sessionId
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Assessment failed');
        }
        
        if (data.success && data.session_id) {
            // Show multi-agent progress if enabled
            multiAgentProgress.style.display = 'block';
            
            // Connect to progress stream
            connectProgressStream(sessionId, inputText, useCache);
        }
        
    } catch (error) {
        errorMsg.innerHTML = `<div class="error">❌ ${error.message}</div>`;
        loading.classList.remove('active');
        submitBtn.disabled = false;
    }
}

/**
 * Reset all progress stage indicators to initial state
 */
function resetProgressStages() {
    const stages = document.querySelectorAll('.progress-stage');
    stages.forEach(stage => {
        stage.className = 'progress-stage';
        const statusElement = stage.querySelector('.progress-status');
        if (statusElement) {
            statusElement.textContent = 'pending';
        }
        
        // Reset icon based on stage
        const iconElement = stage.querySelector('.progress-icon');
        const stageType = stage.getAttribute('data-stage');
        if (iconElement) {
            switch(stageType) {
                case 'preparation':
                    iconElement.textContent = '⏳';
                    break;
                case 'research':
                    iconElement.textContent = '🔍';
                    break;
                case 'verification':
                    iconElement.textContent = '✅';
                    break;
                case 'synthesis':
                    iconElement.textContent = '📝';
                    break;
            }
        }
    });
}
