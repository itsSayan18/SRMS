// File upload preview
function previewFile(input, previewId) {
    const preview = document.getElementById(previewId);
    const file = input.files[0];
    const reader = new FileReader();

    reader.onloadend = function () {
        preview.src = reader.result;
    }

    if (file) {
        reader.readAsDataURL(file);
    } else {
        preview.src = "";
    }
}

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
    }
    form.classList.add('was-validated');
}

// Dynamic form fields
function addFormField(containerId, template) {
    const container = document.getElementById(containerId);
    const newField = template.cloneNode(true);
    container.appendChild(newField);
}

function removeFormField(button) {
    button.closest('.form-group').remove();
}

// Flash message auto-hide
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 3000);
    });
});

// File size validation
function validateFileSize(input, maxSize) {
    const file = input.files[0];
    if (file && file.size > maxSize * 1024 * 1024) {
        alert(`File size must be less than ${maxSize}MB`);
        input.value = '';
        return false;
    }
    return true;
}

// Password strength meter
function checkPasswordStrength(password) {
    let strength = 0;
    if (password.match(/[a-z]+/)) strength += 1;
    if (password.match(/[A-Z]+/)) strength += 1;
    if (password.match(/[0-9]+/)) strength += 1;
    if (password.match(/[$@#&!]+/)) strength += 1;
    
    return strength;
}

function updatePasswordStrength(input, meterId) {
    const meter = document.getElementById(meterId);
    const strength = checkPasswordStrength(input.value);
    
    meter.value = strength;
    meter.className = strength > 2 ? 'is-valid' : 'is-invalid';
}

// Data table sorting
function sortTable(table, column) {
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    const direction = table.dataset.sortDir === 'asc' ? -1 : 1;
    
    rows.sort((a, b) => {
        const aCol = a.children[column].textContent.trim();
        const bCol = b.children[column].textContent.trim();
        return aCol > bCol ? direction : -direction;
    });
    
    table.dataset.sortDir = direction === 1 ? 'asc' : 'desc';
    
    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
}

// Export table to CSV
function exportTableToCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    const rows = table.querySelectorAll('tr');
    
    let csv = [];
    for (let i = 0; i < rows.length; i++) {
        const row = [], cols = rows[i].querySelectorAll('td, th');
        
        for (let j = 0; j < cols.length; j++) {
            let data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/(\s\s)/gm, ' ');
            data = data.replace(/"/g, '""');
            row.push('"' + data + '"');
        }
        csv.push(row.join(','));
    }
    
    const csvFile = new Blob([csv.join('\n')], { type: 'text/csv' });
    const downloadLink = document.createElement('a');
    downloadLink.download = filename;
    downloadLink.href = window.URL.createObjectURL(csvFile);
    downloadLink.style.display = 'none';
    document.body.appendChild(downloadLink);
    downloadLink.click();
} 