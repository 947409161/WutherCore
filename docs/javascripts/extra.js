document$.subscribe(() => {
  for (const link of document.querySelectorAll(".md-content a[href^='http']")) {
    if (link.hostname !== window.location.hostname) {
      link.setAttribute("rel", "noopener noreferrer");
    }
  }
});
