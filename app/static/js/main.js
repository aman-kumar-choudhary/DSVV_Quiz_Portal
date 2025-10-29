document.addEventListener('DOMContentLoaded', () => {
    const quizContainer = document.getElementById('quiz-container');
    const nextButton = document.getElementById('next-question');
    const submitButton = document.getElementById('submit-quiz');
    const timerDisplay = document.getElementById('timer');
    let timeLeft = 600; // Default 10 minutes
    let timer;

    function startTimer() {
        timer = setInterval(() => {
            timeLeft--;
            document.getElementById('time-left').textContent = timeLeft;
            if (timeLeft <= 0) {
                clearInterval(timer);
                window.location.href = '/feedback';
            }
        }, 1000);
    }

    function loadQuestion(question) {
        quizContainer.innerHTML = `
            <p class="font-medium mb-2">Question ${question.question_id}: ${question.text}</p>
            ${question.options.map((option, i) => `
                <label class="block mb-1">
                    <input type="radio" name="answer" value="${option}" class="mr-2">
                    ${option}
                </label>
            `).join('')}
        `;
    }

    fetch('/api/get_questions')
        .then(response => response.json())
        .then(questions => {
            if (questions.length > 0) {
                loadQuestion(questions[0]);
                nextButton.style.display = 'block';
                if (!timer) startTimer(); // Only start timer if questions are available
            } else {
                quizContainer.innerHTML = '<p class="text-red-500">No questions loaded. Please contact support.</p>';
            }
        })
        .catch(error => {
            console.error('Error loading questions:', error);
            quizContainer.innerHTML = '<p class="text-red-500">Error loading questions. Please try again.</p>';
        });

    nextButton.addEventListener('click', () => {
        const selected = document.querySelector('input[name="answer"]:checked');
        if (selected) {
            fetch('/api/submit_answer', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ answer: selected.value })
            })
            .then(response => response.json())
            .then(() => {
                fetch('/api/next_question', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.finished) {
                        submitButton.style.display = 'block';
                        nextButton.style.display = 'none';
                    } else if (data) {
                        loadQuestion(data);
                    }
                })
                .catch(error => console.error('Error fetching next question:', error));
            })
            .catch(error => console.error('Error submitting answer:', error));
        } else {
            alert('Please select an answer before proceeding.');
        }
    });

    submitButton.addEventListener('click', () => {
        clearInterval(timer);
        window.location.href = '/feedback';
    });

    setInterval(() => {
        fetch('/check_time')
            .then(response => response.json())
            .then(data => {
                if (data.time_up) {
                    clearInterval(timer);
                    window.location.href = '/feedback';
                }
            })
            .catch(error => console.error('Error checking time:', error));
    }, 1000);
});