// Update independent Transfers regions without replacing unchanged controls or
// the shell. Compare generated markup, not live DOM (which contains disclosure
// state and focused controls). Any structural change falls back to a full render.
export function patchRenderRegions(
  app: HTMLElement,
  previousMarkup: string,
  nextMarkup: string,
  bind: (root: HTMLElement) => void
): boolean {
  const previous = document.createElement('template');
  const next = document.createElement('template');
  previous.innerHTML = previousMarkup;
  next.innerHTML = nextMarkup;
  const selector = '[data-render-region]';
  const previousRegions = [...previous.content.querySelectorAll<HTMLElement>(selector)];
  const nextRegions = [...next.content.querySelectorAll<HTMLElement>(selector)];
  const liveRegions = [...app.querySelectorAll<HTMLElement>(selector)];
  if (!previousRegions.length || previousRegions.length !== nextRegions.length || nextRegions.length !== liveRegions.length) return false;
  const keys = nextRegions.map(region => region.dataset.renderRegion);
  if (new Set(keys).size !== keys.length || keys.some((key, index) => !key
    || previousRegions[index].dataset.renderRegion !== key || liveRegions[index].dataset.renderRegion !== key)) return false;
  const updates = nextRegions.map((region, index) => ({
    live: liveRegions[index],
    previous: previousRegions[index].innerHTML,
    next: region.innerHTML
  }));
  for (const region of [...previousRegions, ...nextRegions]) region.replaceChildren();
  if (previous.innerHTML !== next.innerHTML) return false;
  for (const update of updates) {
    if (update.previous === update.next) continue;
    const disclosures = [...update.live.querySelectorAll<HTMLDetailsElement>('details')]
      .map(detail => ({ summary: detail.querySelector('summary')?.innerHTML, open: detail.open, focused: detail.querySelector('summary') === document.activeElement }));
    update.live.innerHTML = update.next;
    // Preserve disclosure choices only when their exact summaries still match.
    [...update.live.querySelectorAll<HTMLDetailsElement>('details')].forEach((detail, index) => {
      if (disclosures[index]?.summary !== detail.querySelector('summary')?.innerHTML) return;
      detail.open = disclosures[index].open;
      if (disclosures[index].focused) detail.querySelector('summary')?.focus({ preventScroll: true });
    });
    bind(update.live);
  }
  return true;
}
