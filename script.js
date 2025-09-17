// Load playbooks.json and populate dropdown
fetch('playbooks.json')
  .then(response => response.json())
  .then(data => {
    window.playbooks = data; // store globally
    const dropdown = document.getElementById("incident");

    Object.keys(playbooks).forEach(key => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = key;
      dropdown.appendChild(option);
    });
  });

// Generate playbook
function generatePlaybook() {
  const type = document.getElementById("incident").value;
  const steps = window.playbooks[type];
  const output = document.getElementById("output");
  output.innerHTML = `<h2>${type} Response Steps</h2>`;
  let list = "<ol>";
  steps.forEach(step => { list += `<li>${step}</li>`; });
  list += "</ol>";
  output.innerHTML += list;
}

// Download as PDF
function downloadPDF() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  doc.text(document.getElementById("output").innerText, 10, 10);
  doc.save("incident-playbook.pdf");
}