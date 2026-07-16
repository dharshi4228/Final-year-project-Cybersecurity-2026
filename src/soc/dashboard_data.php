// Update KPI Cards
fetch('stats.php')
.then(res => res.json())
.then(data => {
document.getElementById('totalAttacks').innerText = data.totalAttacks;
document.getElementById('uniqueIPs').innerText = data.uniqueIPs;
document.getElementById('totalCommands').innerText = data.totalCommands;
document.getElementById('malwareSamples').innerText = data.malwareSamples;
});

// Overview chart (Honeypot counts)
fetch('top_users.php')
.then(res => res.json())
.then(data => {
new Chart(document.getElementById('overviewChart'), {
type:'doughnut',
data:{
labels: data.labels, // e.g. ['Cowrie','Dionaea']
datasets:[{data:data.counts, backgroundColor:['#1f77b4','#2ca02c','#d62728']}]
}
});
});

// SSH chart (top IPs)
fetch('top_ips.php')
.then(res => res.json())
.then(data => {
new Chart(document.getElementById('sshChart'), {
type:'bar',
data:{
labels:data.labels,
datasets:[{label:'Attempts', data:data.counts, backgroundColor:'#1f77b4'}]
}
});
});

// Attacker timeline
fetch('timeline.php')
.then(res=>res.json())
.then(data=>{
new Chart(document.getElementById('attackerChart'), {
type:'line',
data:{
labels:data.labels,
datasets:[{
label:'Attacks',
data:data.counts,
borderColor:'#2ca02c',
backgroundColor:'rgba(44,160,44,0.3)',
fill:true
}]
}
});
});

// Optional: Malware chart using events.php or mitre.php
fetch('events.php')
.then(res=>res.json())
.then(data=>{
const malwareLabels = data.map(item=>item.malware_name);
const malwareCounts = data.map(item=>item.count);
new Chart(document.getElementById('malwareChart'),{
type:'bar',
data:{
labels:malwareLabels,
datasets:[{label:'Samples', data:malwareCounts, backgroundColor:'#d62728'}]
}
});
});