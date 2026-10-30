// Test cases for o06-javascript-insecure-code.yaml, as code a model might write in a reply.

function calculate(expression) {
  // ruleid: llmaudit-o06-js-eval
  const total = eval(expression);
  // ruleid: llmaudit-o06-js-eval
  const fn = new Function("a", expression);
  // ok: llmaudit-o06-js-eval
  const two = eval("1 + 1");
  // ok: llmaudit-o06-js-eval
  const add = new Function("a", "b", "return a + b");
  return [total, fn, two, add];
}

function render(element, message) {
  // ruleid: llmaudit-o06-js-html-injection
  element.innerHTML = message;
  // ruleid: llmaudit-o06-js-html-injection
  document.write("<p>" + message + "</p>");
  // ok: llmaudit-o06-js-html-injection
  element.textContent = message;
  // ok: llmaudit-o06-js-html-injection
  element.innerHTML = "<p>Loading...</p>";
}
