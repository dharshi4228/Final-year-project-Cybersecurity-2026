<!DOCTYPE html>
<html>

<head>
    <title>MITRE ATT&CK Mapping</title>
    <link rel="stylesheet" href="assets/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body>

    <h1>MITRE ATT&CK – Observed Techniques</h1>

    <table id="mitreTable" border="1" cellpadding="8" width="100%">
        <thead>
            <tr>
                <th>Tactic</th>
                <th>Technique</th>
                <th>Technique ID</th>
                <th>Observed Count</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

    <br>
    <canvas id="mitreChart" height="120"></canvas>

    <script>
        fetch('api/mitre.php')
            .then(r => r.json())
            .then(data => {

                const tbody = document.querySelector('#mitreTable tbody');
                const labels = [];
                const counts = [];

                data.forEach(row => {
                    labels.push(row.technique_id);
                    counts.push(row.total);

                    tbody.innerHTML += `
        <tr>
          <td>${row.tactic}</td>
          <td>${row.technique}</td>
          <td><b>${row.technique_id}</b></td>
          <td>${row.total}</td>
        </tr>
      `;
                });

                new Chart(mitreChart, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'MITRE Technique Count',
                            data: counts
                        }]
                    }
                });
            });
    </script>

</body>

</html>