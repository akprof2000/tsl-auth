// Подтверждение опасных действий без inline-обработчиков (совместимо со строгим CSP).
document.addEventListener("submit", function (e) {
  var message = e.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) e.preventDefault();
});

// «Глазок» для полей пароля: показать/скрыть вводимое значение.
// Подписи берутся из data-атрибутов <body> (макет выводит их на языке страницы), в скрипте — только запасные.
document.addEventListener("DOMContentLoaded", function () {
  var showText = document.body.getAttribute("data-password-show") || "Show password";
  var hideText = document.body.getAttribute("data-password-hide") || "Hide password";
  document.querySelectorAll('input[type="password"]').forEach(function (input) {
    var wrap = document.createElement("span");
    wrap.className = "password-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    var button = document.createElement("button");
    button.type = "button";
    button.className = "password-toggle";
    button.setAttribute("aria-label", showText);
    button.title = showText;
    button.textContent = "👁";
    button.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "🙈" : "👁";
      button.title = show ? hideText : showText;
      button.setAttribute("aria-label", button.title);
      input.focus();
    });
    wrap.appendChild(button);
  });
});
