// Drag-and-drop for the upload form. The form works without JavaScript.
(function () {
  "use strict";
  var drop = document.getElementById("drop");
  if (!drop) return;
  var input = drop.querySelector('input[type="file"]');
  var label = drop.querySelector("strong");

  function show(file) {
    if (file) label.textContent = file.name;
  }

  ["dragenter", "dragover"].forEach(function (name) {
    drop.addEventListener(name, function (event) {
      event.preventDefault();
      drop.classList.add("is-over");
    });
  });
  ["dragleave", "drop"].forEach(function (name) {
    drop.addEventListener(name, function () {
      drop.classList.remove("is-over");
    });
  });
  drop.addEventListener("drop", function (event) {
    event.preventDefault();
    if (!event.dataTransfer || !event.dataTransfer.files.length) return;
    input.files = event.dataTransfer.files;
    show(input.files[0]);
  });
  input.addEventListener("change", function () {
    show(input.files[0]);
  });
})();
