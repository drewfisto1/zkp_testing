const snarkjs = window.snarkjs;

document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("auth-form");
    const toggleBtn = document.getElementById("toggle-btn");
    const submitBtn = document.getElementById("submit-btn");
    const formTitle = document.getElementById("form-title");
    const errMsg = document.getElementById("err-msg");

    let isRegistering = false;

    toggleBtn.addEventListener("click", () => {
        isRegistering = !isRegistering;
        submitBtn.textContent = isRegistering ? "Register" : "Login";
        formTitle.textContent = isRegistering ? "Register" : "Login";
        toggleBtn.textContent = isRegistering ? "Switch to Login" : "Switch to Register";
        errMsg.textContent = "";
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        errMsg.textContent = "";

        let username = document.getElementById("username").value;
        let password = document.getElementById("password").value;
        form.reset();

        if (isRegistering) {
            let salt, saltArray;
            try {
                const res = await fetch("/register/init", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username })
                });

                if (!res.ok) throw new Error("Salt fetch failed");

                const json = await res.json();
                salt = json.salt;
                saltArray = hexToSaltArray(salt)

            } catch (err) {
                errMsg.textContent = "Failed to register (salt error)";
                return;
            }

            const passwordField = passwordToField(password)

            const input = {
                password: passwordField,
                salt: saltArray,
                nonce: ["0"]
            };
            
            const wasmBufferRaw = await fetchArrayBuffer("/password_js/password.wasm");
            const zkeyBufferRaw = await fetchArrayBuffer("/password_js/password_final.zkey");

            const wasmBuffer = new Uint8Array(wasmBufferRaw);
            const zkeyBuffer = new Uint8Array(zkeyBufferRaw)

            try {
                const { publicSignals } = await snarkjs.groth16.fullProve(
                    input,
                    wasmBuffer,
                    zkeyBuffer
                );

                const expectedHash = publicSignals[0];

                const res = await fetch("/register/complete", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, expectedHash })
                });

                if (res.ok) {
                    errMsg.textContent = "Registration successful! You can now log in.";
                    toggleBtn.click();
                } else {
                    errMsg.textContent = "Registration failed";
                }
            } catch (err) {
                errMsg.textContent = "ZKP failed (register)" + err;
            }

        } else {
            let salt, nonce;
            try {
                const res = await fetch("/salt-nonce", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username })
                });

                if (!res.ok) throw new Error("Salt/nonce fetch failed");

                const json = await res.json();
                salt = json.salt;
                nonce = json.nonce;
            } catch (err) {
                errMsg.textContent = "Login failed (salt/nonce)";
                return;
            }

            const passwordField = passwordToField(password)
            const saltArray = base64ToSaltArray(salt)
            const nonceString = base64ToNumber(nonce)

            const input = {
                password: passwordField,
                salt: saltArray,
                nonce: ["0"]
            };

            const wasmBufferRaw = await fetchArrayBuffer("/password_js/password.wasm");
            const zkeyBufferRaw = await fetchArrayBuffer("/password_js/password_final.zkey");

            const wasmBuffer = new Uint8Array(wasmBufferRaw);
            const zkeyBuffer = new Uint8Array(zkeyBufferRaw)

            try {
                const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                    input,
                    wasmBuffer,
                    zkeyBuffer
                );

                const res = await fetch("/prove", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "include",
                    body: JSON.stringify({ username, proof, publicSignals })
                });

                if (res.ok) {
                    window.location.href = "/secret_layer";
                } else {
                    errMsg.textContent = "Login failed (invalid proof)";
                }
            } catch (err) {
                errMsg.textContent = "ZKP failed (login)" + err;
            }
        }
    });
});


function hexToSaltArray(hex) {
    const salt = [];
    for (let i = 0; i < 32; i += 2) {
        salt.push(parseInt(hex.slice(i, i + 2), 16));
    }
    while (salt.length < 16) salt.push(0); 
    return salt.map(n => n.toString());
}

function passwordToField(password) {
    let result = 0n;
    for (let i = 0; i < password.length; i++) {
        result = (result << 8n) + BigInt(password.charCodeAt(i));
    }

    return result.toString(); 
}


async function fetchFastFile(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch ${url}`);
    const buffer = new Uint8Array(await res.arrayBuffer());
    return new FastFile(buffer);
}

async function fetchArrayBuffer(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Failed to load ${url}`);
    return await response.arrayBuffer();
}

function base64ToSaltArray(base64String) {
    const binaryString = atob(base64String);
    
    const bytes = [];
    for (let i = 0; i < Math.min(binaryString.length, 16); i++) {
        bytes.push(binaryString.charCodeAt(i).toString());
    }
    
    while (bytes.length < 16) {
        bytes.push("0");
    }
    
    return bytes;
}

function base64ToNumber(base64String) {
    const binaryString = atob(base64String);
    let number = 0n;
    for (let i = 0; i < binaryString.length; i++) {
        number = (number << 8n) + BigInt(binaryString.charCodeAt(i));
    }
    return number.toString();
}
  