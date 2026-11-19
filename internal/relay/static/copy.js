// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Copy buttons for the code blocks. Without JS or a clipboard they stay hidden and the text is still selectable.
(function () {
  if (!navigator.clipboard) return;
  document.querySelectorAll("button[data-copy]").forEach(function (b) {
    var pre = document.getElementById(b.getAttribute("data-copy"));
    if (!pre) return;
    b.hidden = false;
    b.addEventListener("click", function () {
      navigator.clipboard.writeText(pre.textContent).then(function () {
        b.textContent = "Copied";
        setTimeout(function () { b.textContent = "Copy"; }, 2000);
      });
    });
  });
})();
