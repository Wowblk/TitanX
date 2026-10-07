import { useState, KeyboardEvent, ChangeEvent } from "react";
import styles from "./TagInput.module.css";

type TagInputProps = {
  id?: string;
  value: string[];
  onChange: (tags: string[]) => void;
  placeholder?: string;
  className?: string;
};

const TagInput = ({ id, value, onChange, placeholder, className }: TagInputProps) => {
  const [text, setText] = useState("");

  const addTag = (raw: string) => {
    const t = raw.trim();
    if (!t) return;
    if (value.includes(t)) {
      setText("");
      return;
    }
    onChange([...value, t]);
    setText("");
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      addTag(text);
    } else if (e.key === "Backspace" && text === "" && value.length > 0) {
      // 便捷删除最后一个标签
      onChange(value.slice(0, -1));
    }
  };

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    setText(e.target.value);
  };

  const removeTag = (t: string) => {
    onChange(value.filter((x) => x !== t));
  };

  return (
    <div className={`${styles.container} ${className ?? ""}`.trim()}>
      <input
        id={id}
        className={styles.input}
        value={text}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        placeholder={placeholder ?? "输入标签后按回车"}
      />
      {value.length > 0 && (
        <div className={styles.chips}>
          {value.map((tag, idx) => (
            <span className={styles.chip} key={`${tag}-${idx}`}>
              <span className={styles.chipText}>{tag}</span>
              <button
                type="button"
                className={styles.remove}
                aria-label={`移除 ${tag}`}
                onClick={() => removeTag(tag)}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

export default TagInput;