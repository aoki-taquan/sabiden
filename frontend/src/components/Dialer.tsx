import { createSignal, For, type Component } from "solid-js";

const KEYS = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"];

export const Dialer: Component<{
  extId: string;
  onCall: (number: string) => void;
  onLogout: () => void;
  status: string;
  statusOk: boolean;
}> = (props) => {
  const [num, setNum] = createSignal("");

  const append = (k: string) => setNum((n) => (n + k).slice(0, 32));
  const back = () => setNum((n) => n.slice(0, -1));

  const call = () => {
    const n = num().trim();
    if (n.length === 0) return;
    props.onCall(n);
  };

  return (
    <div class="container">
      <div class="row" style={{ "justify-content": "space-between", "align-items": "center" }}>
        <div>
          <h2 style={{ margin: 0 }}>{props.extId}</h2>
          <span class={`status ${props.statusOk ? "ok" : "err"}`}>{props.status}</span>
        </div>
        <button onClick={props.onLogout} style={{ padding: "8px 12px" }}>
          ログアウト
        </button>
      </div>

      <input
        type="tel"
        inputmode="tel"
        value={num()}
        onInput={(e) => setNum(e.currentTarget.value.replace(/[^0-9*#+]/g, ""))}
        placeholder="番号を入力"
        style={{ "margin-top": "20px", "font-size": "22px", "text-align": "center" }}
      />

      <div class="dialer">
        <For each={KEYS}>{(k) => <button onClick={() => append(k)}>{k}</button>}</For>
      </div>

      <div class="row">
        <button onClick={back} style={{ flex: 1 }}>
          ←
        </button>
        <button class="primary" onClick={call} style={{ flex: 2 }} disabled={!props.statusOk}>
          発信
        </button>
      </div>
    </div>
  );
};
