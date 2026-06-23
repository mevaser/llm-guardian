let currentLevelId = null;
let currentSessionId = null;

// DOM Elements
const levelList = document.getElementById('level-list');
const levelTitle = document.getElementById('current-level-title');
const levelStatus = document.getElementById('level-status');
const levelObjective = document.getElementById('level-objective');
const levelDescription = document.getElementById('level-description');
const chatHistory = document.getElementById('chat-history');
const chatForm = document.getElementById('chat-form');
const promptInput = document.getElementById('prompt-input');
const submitBtn = document.getElementById('submit-btn');
const attemptsBody = document.getElementById('attempts-body');
const successModal = document.getElementById('success-modal');
const nextLevelBtn = document.getElementById('next-level-btn');

async function init() {
    await fetchLevels();
    
    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await submitPrompt();
    });

    nextLevelBtn.addEventListener('click', () => {
        successModal.classList.add('hidden');
        if (currentLevelId < 8) {
            loadLevel(currentLevelId + 1);
        }
    });
}

async function fetchLevels() {
    try {
        const response = await fetch('/api/levels');
        const levels = await response.json();
        
        levelList.innerHTML = '';
        levels.forEach(level => {
            const btn = document.createElement('button');
            btn.className = 'level-item';
            btn.id = `level-btn-${level.level_id}`;
            btn.innerText = `Level ${level.level_id}: ${level.title}`;
            btn.addEventListener('click', () => loadLevel(level.level_id));
            levelList.appendChild(btn);
        });
    } catch (err) {
        console.error("Failed to fetch levels:", err);
    }
}

async function loadLevel(levelId) {
    try {
        const response = await fetch(`/api/session/start?level_id=${levelId}`, {
            method: 'POST'
        });
        const data = await response.json();
        
        currentSessionId = data.session_id;
        currentLevelId = levelId;
        
        const info = data.level_info;
        
        // Update UI
        document.querySelectorAll('.level-item').forEach(el => el.classList.remove('active'));
        document.getElementById(`level-btn-${levelId}`).classList.add('active');
        
        levelTitle.innerText = `Level ${info.level_id}: ${info.title}`;
        levelObjective.innerText = info.objective;
        levelDescription.innerText = info.public_description;
        
        levelStatus.innerText = 'Not Solved';
        levelStatus.className = 'status-badge';
        
        chatHistory.innerHTML = '';
        appendMessage('bot', info.opening_message, false, true);
        
        promptInput.disabled = false;
        submitBtn.disabled = false;
        promptInput.value = '';
        promptInput.placeholder = "Ask the wizard...";
        promptInput.focus();
        
    } catch (err) {
        console.error("Failed to start session:", err);
    }
}

async function submitPrompt() {
    const prompt = promptInput.value.trim();
    if (!prompt || !currentSessionId) return;
    
    promptInput.disabled = true;
    submitBtn.disabled = true;
    
    // Hide fallback notice initially
    document.getElementById('fallback-notice').classList.add('hidden');
    
    // Add user message to chat
    appendMessage('user', prompt);
    promptInput.value = '';
    
    const responseMode = document.getElementById('response-mode').value;
    
    try {
        const response = await fetch('/api/session/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                session_id: currentSessionId,
                prompt: prompt,
                response_mode: responseMode
            })
        });
        
        const data = await response.json();
        
        const fallbackNotice = document.getElementById('fallback-notice');
        
        if (data.response_mode_requested === 'groq_live') {
            fallbackNotice.classList.remove('hidden');
            if (data.composer_used) {
                fallbackNotice.innerText = 'Groq Live used';
                fallbackNotice.className = 'fallback-notice success';
            } else if (data.fallback) {
                fallbackNotice.innerText = 'Groq fallback: ' + (data.fallback_reason || 'unknown_error');
                fallbackNotice.className = 'fallback-notice warning';
            } else {
                fallbackNotice.classList.add('hidden');
            }
        } else {
            fallbackNotice.classList.remove('hidden');
            fallbackNotice.innerText = 'Deterministic mode';
            fallbackNotice.className = 'fallback-notice info';
        }
        
        // Add bot message
        appendMessage('bot', data.response, data.filtered);
        
        if (data.solved) {
            levelStatus.innerText = 'Solved!';
            levelStatus.className = 'status-badge solved';
            document.getElementById(`level-btn-${currentLevelId}`).classList.add('solved');
            promptInput.disabled = true;
            submitBtn.disabled = true;
            promptInput.placeholder = "Level complete!";
            
            setTimeout(() => {
                successModal.classList.remove('hidden');
            }, 1000);
        } else {
            promptInput.disabled = false;
            submitBtn.disabled = false;
            promptInput.placeholder = "Ask the wizard...";
            promptInput.focus();
        }
        
    } catch (err) {
        console.error("Failed to submit prompt:", err);
        promptInput.disabled = false;
        submitBtn.disabled = false;
    }
}

function appendMessage(sender, text, filtered = false, isOpening = false) {
    const div = document.createElement('div');
    div.className = `message ${sender}-message`; // e.g. user-message, bot-message
    
    if (sender === 'user') {
        div.setAttribute('data-testid', 'user-message');
    } else {
        if (isOpening) {
            div.setAttribute('data-testid', 'opening-message');
            div.classList.add('opening-message');
        } else {
            div.setAttribute('data-testid', 'wizard-message');
        }
    }
    
    if (filtered) {
        div.classList.add('filtered');
        div.setAttribute('data-testid', 'filtered-indicator');
    }
    
    div.innerText = text;
    chatHistory.appendChild(div);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

// Start
init();
