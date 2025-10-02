// static/inactivity.js

(function() {
    let warningTimer;
    let logoutTimer;

    const warningTime = 3 * 60 * 1000; // 3 minutos en milisegundos
    const logoutTime = 5 * 60 * 1000;  // 5 minutos en milisegundos

    const inactivityModal = document.getElementById('inactivity-modal');
    const stayConnectedBtn = document.getElementById('stay-connected-btn');

    function showWarningModal() {
        if (inactivityModal) {
            inactivityModal.classList.remove('hidden');
        }
    }

    function hideWarningModal() {
        if (inactivityModal) {
            inactivityModal.classList.add('hidden');
        }
    }

    function logout() {
        // Redirigimos a la ruta de logout que ya creamos en Flask
        window.location.href = '/logout';
    }

    function resetTimers() {
        // Limpiamos los temporizadores existentes
        clearTimeout(warningTimer);
        clearTimeout(logoutTimer);

        // Ocultamos el modal si estaba visible
        hideWarningModal();

        // Creamos los nuevos temporizadores
        warningTimer = setTimeout(showWarningModal, warningTime);
        logoutTimer = setTimeout(logout, logoutTime);
    }

    // --- Event Listeners ---

    // Cualquier actividad del usuario resetea los temporizadores
    window.addEventListener('mousemove', resetTimers, false);
    window.addEventListener('mousedown', resetTimers, false);
    window.addEventListener('keypress', resetTimers, false);
    window.addEventListener('touchmove', resetTimers, false);
    window.addEventListener('scroll', resetTimers, false);

    // Si el usuario hace clic en "Permanecer Conectado", también se resetean
    if (stayConnectedBtn) {
        stayConnectedBtn.addEventListener('click', resetTimers);
    }

    // Iniciamos los temporizadores cuando la página carga
    resetTimers();

})(); // Esta es una función autoejecutable