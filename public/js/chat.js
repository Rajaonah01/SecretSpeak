  const socket = io();
        const userId = document.getElementById("userId").value;
        const receiverIdInput = document.getElementById("receiverId");
        const anonymousModeCheckbox = document.getElementById("anonymousMode");

        const userItems = document.querySelectorAll(".user-item");
        userItems.forEach(item => {
            item.addEventListener("click", () => {
                const receiverId = item.dataset.userId;
                receiverIdInput.value = receiverId; 
             
                
                document.getElementById("chat").style.display = "flex";
                document.getElementById("messages").innerHTML = "";
                
                loadMessages();
            });
        });

       
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

             
                messageDiv.textContent = message.anonymous ? "Anonyme: " + message.content : message.content;
                messagesContainer.appendChild(messageDiv);
            });

        
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

       
            socket.emit("message", { senderId: userId, receiverId, content, anonymous: isAnonymous });

         
            saveMessage(content, receiverId, isAnonymous);

          
            document.getElementById("messageContent").value = ""; 
        });

     
        function saveMessage(content, receiverId, anonymous) {
            const messages = JSON.parse(localStorage.getItem(`chatMessages_${userId}_${receiverId}`)) || [];
            
            const newMessage = {
                senderId: userId,
                receiverId: receiverId,
                content: content,
                anonymous: anonymous
            };
            
            messages.push(newMessage);

         
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

         
            messageDiv.textContent = data.anonymous ? "Anonyme: " + data.content : data.content;
            document.getElementById("messages").appendChild(messageDiv);

      
            saveMessage(data.content, data.receiverId, data.anonymous);

            const messagesContainer = document.getElementById("messages");
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        });

        document.addEventListener('DOMContentLoaded', () => {
         
            const userItems = document.querySelectorAll('.user-item');
            const receiverNameElement = document.getElementById('receiverName');
            const receiverIdInput = document.getElementById('receiverId');
        
            userItems.forEach(userItem => {
                userItem.addEventListener('click', () => {
                
                    const userName = userItem.querySelector('.user-name').textContent;
                    const userId = userItem.getAttribute('data-user-id');
                    receiverNameElement.textContent = userName;
        
                 
                    receiverIdInput.value = userId;
        
               
                    userItems.forEach(item => item.classList.remove('selected'));
                    userItem.classList.add('selected');
                });
            });
        });
        