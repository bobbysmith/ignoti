import langBash from 'highlight.js/lib/languages/bash';
import langJson from 'highlight.js/lib/languages/json';
import langTs from 'highlight.js/lib/languages/typescript';
import Markdown from 'react-markdown';
import { useNavigate } from 'react-router-dom';
import rehypeHighlight from 'rehype-highlight';
import remarkGfm from 'remark-gfm';
import { Header } from '../components/Header';
import 'highlight.js/styles/base16/material-darker.css';

const rehypeHighlightOptions = {
  languages: { bash: langBash, typescript: langTs, ts: langTs, json: langJson },
};

function mdPathToRoute(href: string): string | null {
  const match = href.match(/^\.\/([^.]+)\.md$/);
  if (!match) return null;
  return `/docs/${match[1]}`;
}

export function DocPage({
  title,
  slug,
  content,
}: {
  title: string;
  slug: string;
  content: string;
}) {
  const body = content.replace(/^#[^\n]*\n/, '');
  const navigate = useNavigate();

  return (
    <>
      <Header slug={slug} />
      <main className="app-main">
        <h1>{title}</h1>
        <Markdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[[rehypeHighlight, rehypeHighlightOptions]]}
          components={{
            a({ href, children }) {
              const route = href ? mdPathToRoute(href) : null;
              if (route) {
                return (
                  <a
                    href={route}
                    onClick={e => {
                      e.preventDefault();
                      navigate(route);
                    }}
                  >
                    {children}
                  </a>
                );
              }
              return (
                <a href={href} target="_blank" rel="noreferrer">
                  {children}
                </a>
              );
            },
          }}
        >
          {body}
        </Markdown>
      </main>
    </>
  );
}
