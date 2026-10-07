import type { SVGProps } from "react";

export type IconProps = SVGProps<SVGSVGElement>;

const createIcon = (path: JSX.Element) => (props: IconProps) => (
  <svg
    width={props.width ?? 24}
    height={props.height ?? 24}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={1.6}
    strokeLinecap="round"
    strokeLinejoin="round"
    {...props}
  >
    {path}
  </svg>
);

export const HomeIcon = createIcon(
  <>
    <path d="M3.6 10.3 11.1 3.8a1.3 1.3 0 0 1 1.7 0l7.6 6.5" />
    <path d="M5.5 9.5V19a1 1 0 0 0 1 1h10.9a1 1 0 0 0 1-1v-9.4" />
    <path d="M9.5 20V13h5v7" />
  </>
);

export const SearchIcon = createIcon(
  <>
    <circle cx="10.6" cy="10.6" r="5.8" />
    <path d="m16.2 16.2 4.2 4.2" />
  </>
);

export const CreateIcon = createIcon(
  <>
    <path d="M5.5 19v-5.1a2 2 0 0 1 2-2h3.3" />
    <path d="M5.5 19h4.6" />
    <path d="M13.6 5.4c.8-.8 2-.8 2.8 0l1.7 1.7c.8.8.8 2 0 2.8L12 15l-3.4.9.9-3.4z" />
  </>
);

export const DraftIcon = createIcon(
  <>
    <path d="M6.5 4.5h7.8l3.2 3.2v11.8h-11a1 1 0 0 1-1-1v-13a1 1 0 0 1 1-1z" />
    <path d="M14 4.8V8h3.2" />
    <path d="M8.8 12h6.4M8.8 15.5h4.4" />
  </>
);

export const StudyIcon = createIcon(
  <>
    <path d="M4 7.5 12 4l8 3.5-8 3.6z" />
    <path d="m6.8 16.4 5.2-2.2 5.2 2.2M20 7.6V16" />
    <path d="m4 7.6 0 8.4a2 2 0 0 0 1.2 1.8l5.6 2.4" />
  </>
);

export const ProfileIcon = createIcon(
  <>
    <circle cx="12" cy="8.3" r="3.2" />
    <path d="M6.2 19.6a6.6 6.6 0 0 1 11.6 0" />
  </>
);

export const SparkIcon = createIcon(
  <>
    <path d="m12 2.8 1.5 4.6h4.9l-3.9 2.9 1.4 4.7L12 12.7 8.1 15l1.4-4.7-3.9-2.9h4.9z" />
  </>
);

export const ArrowRightIcon = createIcon(
  <>
    <path d="m10 7 5 5-5 5" />
    <path d="M5 12h10" />
  </>
);

export const HeartIcon = createIcon(
  <>
    <path d="M12 19c-4.8-2.7-7.5-5.6-7.5-9a4.5 4.5 0 0 1 8.2-2.4h.6A4.5 4.5 0 0 1 19.5 10c0 3.4-2.7 6.3-7.5 9z" />
  </>
);

export const BookmarkIcon = createIcon(
  <>
    <path d="M7.5 4h9a1 1 0 0 1 1 1v14l-5.5-3.5L6.5 19V5a1 1 0 0 1 1-1z" />
  </>
);
