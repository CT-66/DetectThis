(function () {
  const input = document.getElementById("sample-input");
  const dropzone = document.getElementById("dropzone");
  const filename = document.getElementById("dz-filename");
  if (!input || !dropzone) return;

  function showName(name) {
    filename.textContent = name || "or click to choose a file";
  }

  input.addEventListener("change", () => {
    showName(input.files[0] && input.files[0].name);
  });

  ["dragenter", "dragover"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("drag-over");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-over");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files && files.length) {
      input.files = files;
      showName(files[0].name);
    }
  });
})();
