export type ContentTag = string;

export type Mentor = {
  id: string;
  name: string;
  alias?: string;
  description?: string;
};

export type ContentKind = "course" | "article" | "video";

export type ContentItem = {
  id: string;
  title: string;
  summary: string;
  tags: ContentTag[];
  isFree: boolean;
  coverImage?: string;
  likes: number;
  views: number;
  mentor: Mentor;
  kind: ContentKind;
  category: string;
  createdAt: string;
  body?: string;
};

export type SearchSuggestion = {
  id: string;
  label: string;
};
