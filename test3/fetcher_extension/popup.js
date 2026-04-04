// popup/popup.js

const authBtn = document.getElementById("auth-btn");
const authDot = document.getElementById("auth-dot");
const note    = document.getElementById("note");

// Check if already authed (non-interactive)
chrome.runtime.sendMessage({ type: "GET_AUTH_TOKEN" }, (response) => {
  if (response?.ok) {
    setAuthed();
  }
});

authBtn.addEventListener("click", () => {
  authBtn.disabled   = true;
  authBtn.textContent = "Connecting...";

  chrome.runtime.sendMessage({ type: "GET_AUTH_TOKEN" }, (response) => {
    if (response?.ok) {
      setAuthed();
    } else {
      authBtn.disabled    = false;
      authBtn.textContent = "Connect Gmail Account";
      note.textContent    = "Auth failed: " + (response?.error || "Unknown error");
      note.style.color    = "#a32d2d";
    }
  });
});

function setAuthed() {
  authDot.classList.add("active");
  authBtn.disabled    = true;
  authBtn.textContent = "✓ Connected";
  authBtn.style.background = "#639922";
  note.textContent    = "Ready! Open an email in Gmail to scan it.";
  note.style.color    = "#3b6d11";
}
