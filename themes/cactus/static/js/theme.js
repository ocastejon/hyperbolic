// Toggle theme

const theme = window.localStorage && window.localStorage.getItem("theme");
const themeToggleArray = document.querySelectorAll(".theme-toggle");
const isDark = theme === "dark";

if (theme !== null) {
  document.body.classList.toggle("dark", isDark);
}

themeToggleArray.forEach(function(themeToggle) {
  themeToggle.addEventListener("click", () => {
    document.body.classList.toggle("dark");
    window.localStorage &&
      window.localStorage.setItem(
        "theme",
        document.body.classList.contains("dark") ? "dark" : "white"
      );
  })
});
