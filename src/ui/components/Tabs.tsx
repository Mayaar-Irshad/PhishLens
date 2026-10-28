import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { panelId, tabId } from './tabIds';

export interface TabDefinition<Id extends string> {
  id: Id;
  label: string;
  count?: number;
}

interface TabsProps<Id extends string> {
  tabs: readonly TabDefinition<Id>[];
  selected: Id;
  onSelect: (id: Id) => void;
  idPrefix: string;
  label: string;
}

/** WAI-ARIA tabs with roving tabindex and arrow-key, Home and End navigation. */
export function Tabs<Id extends string>({
  tabs,
  selected,
  onSelect,
  idPrefix,
  label,
}: TabsProps<Id>) {
  const refs = useRef(new Map<Id, HTMLButtonElement>());
  const list = useRef<HTMLDivElement>(null);

  // When the row scrolls sideways, keep the selected tab in view, including after a
  // selection made elsewhere on the page (such as "View all findings").
  useEffect(() => {
    const row = list.current;
    const button = refs.current.get(selected);
    if (!row || !button || row.scrollWidth <= row.clientWidth) return;
    row.scrollLeft = button.offsetLeft - (row.clientWidth - button.offsetWidth) / 2;
  }, [selected]);

  const move = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next: number | null = null;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    if (next === null) return;
    event.preventDefault();
    const target = tabs[next];
    if (!target) return;
    onSelect(target.id);
    refs.current.get(target.id)?.focus();
  };

  return (
    <div ref={list} className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, index) => {
        const isSelected = tab.id === selected;
        return (
          <button
            key={tab.id}
            ref={(element) => {
              if (element) refs.current.set(tab.id, element);
              else refs.current.delete(tab.id);
            }}
            type="button"
            role="tab"
            id={tabId(idPrefix, tab.id)}
            aria-selected={isSelected}
            aria-controls={panelId(idPrefix, tab.id)}
            tabIndex={isSelected ? 0 : -1}
            onClick={() => onSelect(tab.id)}
            onKeyDown={(event) => move(event, index)}
          >
            {tab.label}
            {tab.count !== undefined && <span className="tabs__count">{tab.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

interface TabPanelProps {
  idPrefix: string;
  id: string;
  children: ReactNode;
}

export function TabPanel({ idPrefix, id, children }: TabPanelProps) {
  return (
    <div
      className="tab-panel"
      role="tabpanel"
      id={panelId(idPrefix, id)}
      aria-labelledby={tabId(idPrefix, id)}
      tabIndex={0}
    >
      {children}
    </div>
  );
}
