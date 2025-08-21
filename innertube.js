// Add ffmpeg.wasm
import { createFFmpeg, fetchFile } from 'https://cdn.jsdelivr.net/npm/@ffmpeg/ffmpeg@0.12.6/dist/ffmpeg.min.js';

const ffmpeg = createFFmpeg({ log: true });
let audioCache = null; // best audio cached

async function initFFmpeg() {
  if (!ffmpeg.isLoaded()) {
    await ffmpeg.load();
  }
}

// pick best audio
function getBestAudio(adaptiveFormats) {
  return adaptiveFormats
    .filter(x => x.mimeType.includes("audio"))
    .sort((a,b)=>parseInt(b.bitrate)-parseInt(a.bitrate))[0];
}

// merge adaptive video + audio
async function mergeVideoAudio(videoUrl, audioUrl, title) {
  await initFFmpeg();

  const videoData = await fetchFile(videoUrl);
  const audioData = await fetchFile(audioUrl);

  ffmpeg.FS('writeFile', 'video.mp4', videoData);
  ffmpeg.FS('writeFile', 'audio.mp3', audioData);

  await ffmpeg.run('-i', 'video.mp4', '-i', 'audio.mp3', '-c:v', 'copy', '-c:a', 'aac', 'output.mp4');

  const data = ffmpeg.FS('readFile', 'output.mp4');
  const url = URL.createObjectURL(new Blob([data.buffer], { type: 'video/mp4' }));

  const a = document.createElement("a");
  a.href = url;
  a.download = `${title}.mp4`;
  a.click();
}

// modified handler
function handleDownloadStreams(info) {
  const ytproDownDiv = document.getElementById("downytprodiv");
  const t = info?.videoDetails?.title.replace(/[\\|?*<>/:"']/g, "");
  const vids = info?.streamingData?.formats;
  const avids = info?.streamingData?.adaptiveFormats;

  // best audio once
  audioCache = getBestAudio(avids);

  ytproDownDiv.innerHTML = `
    <style>
      #tabs {display:flex; gap:10px; margin-bottom:15px;}
      .tab {padding:8px 12px; border-radius:6px; cursor:pointer; background:#ddd;}
      .active {background:#aaa;}
    </style>
    <div id="tabs">
      <div id="tab-video" class="tab active">Video with Audio</div>
      <div id="tab-audio" class="tab">Audio Only</div>
    </div>
    <ul id="listurl"></ul>
  `;

  const list = document.getElementById("listurl");

  // Video with Audio (formats + adaptives merged)
  for (let v of vids) {
    const url = v.url;
    const li = document.createElement("li");
    li.textContent = `${v.qualityLabel} ${formatFileSize((v.bitrate*(v.approxDurationMs/1000))/8)}`;
    li.onclick = () => window.open(url, "_blank");
    list.appendChild(li);
  }

  for (let v of avids) {
    if (!v.mimeType.includes("audio")) {
      const li = document.createElement("li");
      li.textContent = `Adaptive ${v.qualityLabel}`;
      li.onclick = () => mergeVideoAudio(v.url, audioCache.url, t);
      list.appendChild(li);
    }
  }

  // Tab switch
  document.getElementById("tab-video").onclick = () => {
    list.innerHTML = "";
    for (let v of vids) {
      const url = v.url;
      const li = document.createElement("li");
      li.textContent = `${v.qualityLabel}`;
      li.onclick = () => window.open(url, "_blank");
      list.appendChild(li);
    }
    for (let v of avids) {
      if (!v.mimeType.includes("audio")) {
        const li = document.createElement("li");
        li.textContent = `Adaptive ${v.qualityLabel}`;
        li.onclick = () => mergeVideoAudio(v.url, audioCache.url, t);
        list.appendChild(li);
      }
    }
  };

  document.getElementById("tab-audio").onclick = () => {
    list.innerHTML = "";
    for (let a of avids.filter(x => x.mimeType.includes("audio"))) {
      const li = document.createElement("li");
      li.textContent = `Audio ${a.audioQuality}`;
      li.onclick = () => window.open(a.url, "_blank");
      list.appendChild(li);
    }
  };
}
