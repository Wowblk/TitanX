import { useEffect, useMemo, useRef, useState } from "react";
import styles from "./Select.module.css";

export type Option = { label: string; value: string };

type SelectProps = {
  id?: string;
  label?: string;
  value: string;
  options: Option[];
  placeholder?: string;
  onChange: (value: string) => void;
  className?: string;
};

const Select = ({ id, label, value, options, placeholder = "请选择", onChange, className }: SelectProps) => {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState<number>(() => Math.max(0, options.findIndex(o => o.value === value)));
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  const display = useMemo(() => options.find(o => o.value === value)?.label ?? placeholder, [options, value, placeholder]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!wrapperRef.current) return;
      if (!wrapperRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!open && (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ")) {
      setOpen(true);
      e.preventDefault();
      return;
    }
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (e.key === "ArrowDown") {
      setActiveIndex(prev => Math.min(options.length - 1, prev + 1));
    } else if (e.key === "ArrowUp") {
      setActiveIndex(prev => Math.max(0, prev - 1));
    } else if (e.key === "Enter") {
      const opt = options[activeIndex];
      if (opt) onChange(opt.value);
      setOpen(false);
    }
  };

  return (
    <div ref={wrapperRef} className={`${styles.wrapper} ${className ?? ""}`}>
      {label ? (
        <label className={styles.label} htmlFor={id}>
          {label}
        </label>
      ) : null}
      <div
        id={id}
        className={styles.box}
        role="button"
        tabIndex={0}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(prev => !prev)}
        onKeyDown={handleKeyDown}
      >
        <div className={styles.value}>{display}</div>
        <div className={styles.arrow} aria-hidden="true" />
      </div>
      {open ? (
        <div role="listbox" className={styles.menu} aria-labelledby={id}>
          {options.map((opt, idx) => (
            <div
              key={opt.value}
              role="option"
              aria-selected={opt.value === value}
              className={`${styles.option} ${idx === activeIndex ? styles.optionActive : ""} ${
                opt.value === value ? styles.optionSelected : ""
              }`}
              onMouseEnter={() => setActiveIndex(idx)}
              onClick={() => {
                onChange(opt.value);
                setOpen(false);
              }}
            >
              {opt.label}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
};

export default Select;