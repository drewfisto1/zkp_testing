document.addEventListener("DOMContentLoaded", function() {
    document.querySelector("form").addEventListener("submit", function(event) {
        event.preventDefault()
        let username = document.getElementById("username").value;
        let password = document.getElementById("password").value;
        document.querySelector("form").reset();
        
        fetch("/prove", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "username": username,
                "password": password
            }),
            credentials: "include"
        })
        .then(async response => {
            if (response.ok) {
                window.location.href = "/secret_layer";
            }
        })
    })
})
    
    
