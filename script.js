const events = [
    "🟢 Customer Login Successful",
    "🌍 VPN Login Detected from Russia",
    "📱 New Device Detected",
    "💸 Transaction Initiated : ₹8,00,000",
    "🦠 Endpoint Malware Detected",
    "🔥 Firewall Suspicious Traffic Detected"
];

const riskValues = [5, 20, 35, 60, 82, 97];

const explanations = [
    "✔ Login from an unusual country",
    "✔ Unknown device detected",
    "✔ VPN usage identified",
    "✔ High-value transaction",
    "✔ Malware found on endpoint",
    "✔ Firewall detected suspicious outbound traffic"
];

const eventBox = document.getElementById("events");
const riskBox = document.getElementById("risk");
const levelBox = document.getElementById("level");
const aiBox = document.getElementById("ai");
const incidentBox = document.getElementById("incident");
const explanationBox = document.getElementById("explanation");
const actionBox = document.getElementById("action");
const button = document.getElementById("simulate");

button.addEventListener("click", simulateAttack);

function simulateAttack(){

    button.disabled = true;

    eventBox.innerHTML = "";
    explanationBox.innerHTML = "";
    actionBox.innerHTML = "Waiting...";
    incidentBox.innerHTML = "Monitoring...";
    aiBox.innerHTML = "Collecting telemetry...";
    riskBox.innerHTML = "0";
    levelBox.innerHTML = "LOW";

    let index = 0;

    const timer = setInterval(()=>{

        eventBox.innerHTML += `<p>${events[index]}</p>`;

        riskBox.innerHTML = riskValues[index];

        if(riskValues[index] < 30){

            levelBox.innerHTML="LOW";

        }

        else if(riskValues[index] < 70){

            levelBox.innerHTML="MEDIUM";

        }

        else{

            levelBox.innerHTML="HIGH";

        }

        index++;

        if(index===events.length){

            clearInterval(timer);

            correlateEvents();

        }

    },1500);

}

function correlateEvents(){

    aiBox.innerHTML="🤖 Correlating security telemetry...";

    setTimeout(()=>{

        aiBox.innerHTML="🧠 AI has correlated all events into ONE security incident.";

    },2000);

    setTimeout(()=>{

        incidentBox.innerHTML=`

        <h3>🚨 Possible Account Takeover</h3>

        <br>

        <p>Incident ID : INC-24071</p>

        <p>Confidence : 98%</p>

        <p>Risk Score : 97 / 100</p>

        `;

    },3000);

    setTimeout(()=>{

        explanationBox.innerHTML="";

        explanations.forEach(item=>{

            explanationBox.innerHTML += `<p>${item}</p>`;

        });

    },4000);

    setTimeout(()=>{

        actionBox.innerHTML=`

        ✅ Block Transaction<br><br>

        🔒 Lock Customer Account<br><br>

        📲 Trigger Multi-Factor Authentication<br><br>

        📢 Notify SOC Team

        `;

        button.disabled=false;

        button.innerHTML="🔄 Simulate Again";

    },5000);

}