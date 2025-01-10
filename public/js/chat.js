  const socket = io();
        const userId = document.getElementById("userId").value;
        const receiverIdInput = document.getElementById("receiverId");
        const anonymousModeCheckbox = document.getElementById("anonymousMode");

        const userItems = document.querySelectorAll(".user-item");
        userItems.forEach(item => {
            item.addEventListener("click", () => {
                const receiverId = item.dataset.userId;
                receiverIdInput.value = receiverId; 
                // alert(`You are now chatting with user ID ${receiverId}`);
                
                document.getElementById("chat").style.display = "flex";
                document.getElementById("messages").innerHTML = "";
                
                loadMessages();
            });
        });

        // Charger les messages depuis le localStorage
        function loadMessages() {
            const receiverId = receiverIdInput.value;
            const messagesContainer = document.getElementById("messages");
            
            const messages = JSON.parse(localStorage.getItem(`chatMessages_${userId}_${receiverId}`)) || [];

            messages.forEach(message => {
                const messageDiv = document.createElement("div");
                messageDiv.classList.add("message");

                if (message.senderId === userId) {
                    messageDiv.classList.add("sent");
                } else {
                    messageDiv.classList.add("received");
                }

                // Vérifier si le mode anonyme est actif pour afficher "Anonyme"
                messageDiv.textContent = message.anonymous ? "Anonyme: " + message.content : message.content;
                messagesContainer.appendChild(messageDiv);
            });

            // Faire défiler les messages vers le bas
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }

        document.getElementById("messageForm").addEventListener("submit", (e) => {
            e.preventDefault();
            const content = document.getElementById("messageContent").value;
            const receiverId = receiverIdInput.value;
            const isAnonymous = anonymousModeCheckbox.checked;

            if (!receiverId) {
                alert("Please select a user to chat with.");
                return;
            }

            // Envoi du message via le socket
            socket.emit("message", { senderId: userId, receiverId, content, anonymous: isAnonymous });

            // Sauvegarder le message dans le localStorage
            saveMessage(content, receiverId, isAnonymous);

            // Vider le champ de texte
            document.getElementById("messageContent").value = ""; 
        });

        // Sauvegarder le message dans le localStorage
        function saveMessage(content, receiverId, anonymous) {
            const messages = JSON.parse(localStorage.getItem(`chatMessages_${userId}_${receiverId}`)) || [];
            
            const newMessage = {
                senderId: userId,
                receiverId: receiverId,
                content: content,
                anonymous: anonymous
            };
            
            messages.push(newMessage);

            // Sauvegarder les messages dans le localStorage
            localStorage.setItem(`chatMessages_${userId}_${receiverId}`, JSON.stringify(messages));
        }

        socket.on("message", (data) => {
            const messageDiv = document.createElement("div");
            messageDiv.classList.add("message");

            if (data.senderId === userId) {
                messageDiv.classList.add("sent");
            } else {
                messageDiv.classList.add("received");
            }

            // Vérifier si le message est anonyme pour afficher "Anonyme"
            messageDiv.textContent = data.anonymous ? "Anonyme: " + data.content : data.content;
            document.getElementById("messages").appendChild(messageDiv);

            // Sauvegarder le message reçu dans le localStorage
            saveMessage(data.content, data.receiverId, data.anonymous);

            const messagesContainer = document.getElementById("messages");
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        });

        document.addEventListener('DOMContentLoaded', () => {
            // Sélectionner tous les éléments de la liste des utilisateurs
            const userItems = document.querySelectorAll('.user-item');
            const receiverNameElement = document.getElementById('receiverName');
            const receiverIdInput = document.getElementById('receiverId');
        
            userItems.forEach(userItem => {
                userItem.addEventListener('click', () => {
                    // Récupérer les informations de l'utilisateur sélectionné
                    const userName = userItem.querySelector('.user-name').textContent;
                    const userId = userItem.getAttribute('data-user-id');
        
                    // Mettre à jour l'affichage "Discuter avec"
                    receiverNameElement.textContent = userName;
        
                    // Mettre à jour le champ masqué receiverId
                    receiverIdInput.value = userId;
        
                    // Optionnel : Mettre en évidence l'utilisateur sélectionné
                    userItems.forEach(item => item.classList.remove('selected'));
                    userItem.classList.add('selected');
                });
            });
        });
        