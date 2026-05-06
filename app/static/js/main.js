function generatePassword(length = 16) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=?";
    let password = "";
    const cryptoObj = window.crypto || window.msCrypto;
    const array = new Uint32Array(length);
    cryptoObj.getRandomValues(array);
    for (let i = 0; i < length; i++) {
        password += charset[array[i] % charset.length];
    }
    return password;
}

const genBtn = document.getElementById('generatePasswordBtn');
if (genBtn) {
    genBtn.addEventListener('click', () => {
        const field = document.getElementById('passwordField');
        if (field) field.value = generatePassword();
    });
}

// Работа с модальным окном
const showButtons = document.querySelectorAll('.show-password-btn');
const modalEntryId = document.getElementById('modalEntryId');
const decryptBtn = document.getElementById('decryptBtn');
const decryptionResult = document.getElementById('decryptionResult');
const decryptedPassword = document.getElementById('decryptedPassword');
const decryptionError = document.getElementById('decryptionError');
const copyBtn = document.querySelector('#decryptionResult .copy-btn');

function resetModal() {
    decryptionResult.style.display = 'none';
    decryptionError.style.display = 'none';
}

showButtons.forEach(btn => {
    btn.addEventListener('click', function() {
        modalEntryId.value = this.dataset.id;
        resetModal();
        const modal = new bootstrap.Modal(document.getElementById('decryptModal'));
        modal.show();
    });
});

decryptBtn.addEventListener('click', async () => {
    const id = modalEntryId.value;
    try {
        const response = await fetch(`/api/entry/${id}/decrypt`);
        const data = await response.json();
        if (response.ok) {
            decryptedPassword.textContent = data.password;
            decryptionResult.style.display = 'block';
        } else {
            decryptionError.textContent = data.detail || 'Ошибка расшифровки. Проверьте, разблокировано ли хранилище.';
            decryptionError.style.display = 'block';
        }
    } catch (err) {
        decryptionError.textContent = 'Сетевая ошибка';
        decryptionError.style.display = 'block';
    }
});

if (copyBtn) {
    copyBtn.addEventListener('click', () => {
        const text = decryptedPassword.textContent;
        navigator.clipboard.writeText(text).then(() => {
            copyBtn.textContent = '✅';
            setTimeout(() => { copyBtn.textContent = '📋 Копировать'; }, 2000);
        });
    });
}