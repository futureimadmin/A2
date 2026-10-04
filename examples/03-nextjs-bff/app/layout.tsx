export const metadata = {
  title: "A2 Next.js BFF sample",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: 0, background: "#f8fafc" }}>
        {children}
      </body>
    </html>
  );
}
