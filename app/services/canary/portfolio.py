"""Generic portfolio decoy page — identical for every request (OpSec)."""

PORTFOLIO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Portfolio</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Georgia, "Times New Roman", serif;
      color: #1a1a1a;
      background: #faf9f7;
      line-height: 1.6;
    }
    header {
      border-bottom: 1px solid #e0ddd8;
      padding: 2.5rem 1.5rem;
      text-align: center;
      background: #fff;
    }
    header h1 { font-size: 1.75rem; font-weight: 400; letter-spacing: 0.04em; }
    header p { color: #666; margin-top: 0.5rem; font-size: 0.95rem; }
    main { max-width: 42rem; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
    section { margin-bottom: 2.5rem; }
    h2 {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: #888;
      margin-bottom: 1rem;
    }
    ul { list-style: none; }
    li {
      padding: 0.75rem 0;
      border-bottom: 1px solid #eceae6;
    }
    li:last-child { border-bottom: none; }
    .role { font-size: 0.85rem; color: #777; }
    footer {
      text-align: center;
      padding: 2rem;
      font-size: 0.8rem;
      color: #aaa;
    }
  </style>
</head>
<body>
  <header>
    <h1>Selected Work</h1>
    <p>Design &amp; engineering projects</p>
  </header>
  <main>
    <section>
      <h2>Recent</h2>
      <ul>
        <li>
          <div>Platform migration</div>
          <div class="role">Infrastructure · 2024</div>
        </li>
        <li>
          <div>Analytics dashboard</div>
          <div class="role">Data visualization · 2023</div>
        </li>
        <li>
          <div>Brand refresh</div>
          <div class="role">Visual identity · 2022</div>
        </li>
      </ul>
    </section>
    <section>
      <h2>About</h2>
      <p>Independent consultant working across product, systems, and visual design.
      Available for select engagements.</p>
    </section>
  </main>
  <footer>&copy; Portfolio</footer>
</body>
</html>"""
