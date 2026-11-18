// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// The link token rides in the URL fragment so it never reaches a server log. Move it into the form.
(function () {
  var m = /[#&]token=([A-Za-z0-9_-]+)/.exec(window.location.hash);
  var field = document.getElementById("token");
  if (m && field) {
    field.value = m[1];
    history.replaceState(null, "", window.location.pathname);
  }
})();
