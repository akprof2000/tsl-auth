// Подтверждение опасных действий без inline-обработчиков (совместимо со строгим CSP).
document.addEventListener("submit", function (e) {
  var message = e.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) e.preventDefault();
});

// «Глазок» для полей пароля: показать/скрыть вводимое значение.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll('input[type="password"]').forEach(function (input) {
    var wrap = document.createElement("span");
    wrap.className = "password-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    var button = document.createElement("button");
    button.type = "button";
    button.className = "password-toggle";
    button.setAttribute("aria-label", "Показать пароль");
    button.title = "Показать пароль";
    button.textContent = "👁";
    button.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "🙈" : "👁";
      button.title = show ? "Скрыть пароль" : "Показать пароль";
      button.setAttribute("aria-label", button.title);
      input.focus();
    });
    wrap.appendChild(button);
  });
});
