const socket = io();
const userId = document.getElementById("userId").value;
const receiverIdInput = document.getElementById("receiverId");

// Sélectionner un utilisateur pour chatter
const userItems = document.querySelectorAll(".user-item");
userItems.forEach(item => {
    item.addEventListener("click", () => {
        const receiverId = item.dataset.userId;
        receiverIdInput.value = receiverId; // Mettre à jour le champ caché
        alert(`You are now chatting with user ID ${receiverId}`);
        document.getElementById("messages").innerHTML = ""; // Réinitialiser les messages
    });
});

// Envoyer un message
document.getElementById("messageForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const content = document.getElementById("messageContent").value;
    const receiverId = receiverIdInput.value;

    if (!receiverId) {
        alert("Please select a user to chat with.");
        return;
    }

    socket.emit("message", { senderId: userId, receiverId, content });
    document.getElementById("messageContent").value = ""; // Réinitialiser le champ message
});

// Réception des messages
socket.on("message", (data) => {
    const messageDiv = document.createElement("div");
    messageDiv.textContent = `User ${data.senderId}: ${data.content}`;
    document.getElementById("messages").appendChild(messageDiv);
});