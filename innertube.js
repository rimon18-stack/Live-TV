import Jinter from 'https://cdn.jsdelivr.net/npm/jintr@3.3.1/+esm';
import { BG } from 'https://cdn.jsdelivr.net/npm/bgutils-js@3.2.0/dist/index.min.js';
import {Player, ProtoUtils, Utils } from 'https://cdn.jsdelivr.net/npm/youtubei.js@13.4.0/bundle/browser.min.js';

// FFmpeg setup
const { createFFmpeg, fetchFile } = FFmpeg;
let ffmpeg = null;

async function loadFFmpeg() {
    if (!ffmpeg) {
        ffmpeg = createFFmpeg({ log: true });
        await ffmpeg.load();
    }
    return ffmpeg;
}

function write(x) {
    if (typeof x == "object") {
        x = JSON.stringify(x, null, 2);
    }
    var ytproDownDiv = document.getElementById("downytprodiv");
    ytproDownDiv.innerHTML = x;
}

var cver = "19.35.36";
var player_id;
var poToken, visitorData;
var sig_timestamp, nsig_sc, sig_sc;

async function getPo(identifier) {
    const requestKey = 'O43z0dpjhgX20SCx4KAo';
    const bgConfig = {
        fetch: (input, init) => fetch(input, init),
        globalObj: window,
        requestKey,
        identifier
    };

    const bgChallenge = await BG.Challenge.create(bgConfig);
    if (!bgChallenge) throw new Error('Could not get challenge');

    const interpreterJavascript = bgChallenge.interpreterJavascript.privateDoNotAccessOrElseSafeScriptWrappedValue;
    if (interpreterJavascript) {
        new Function(interpreterJavascript)();
    } else throw new Error('Could not load VM');

    const poTokenResult = await BG.PoToken.generate({
        program: bgChallenge.program,
        globalName: bgChallenge.globalName,
        bgConfig
    });

    return poTokenResult.poToken;
}

async function getDeciphers() {
    return new Promise(async (resolve, reject) => {
        var scripts = document.getElementsByTagName('script');
        for (var i = 0; i < scripts.length; i++) {
            if (scripts[i].src.indexOf("/base.js") > 0) {
                player_id = scripts[i].src.match("(?<=player/).*(?=/player)");
            }
        }

        visitorData = ProtoUtils.encodeVisitorData(Utils.generateRandomString(11), Math.floor(Date.now() / 1000));
        write("Fetching PoTokens...");

        await getPo(visitorData).then((webPo) => poToken = webPo);
        write("Fetching Player JS...");

        var player_js = await fetch(`https://www.youtube.com/s/player/${player_id}/player_ias.vflset/en_US/base.js`).then(x => x.text());
        const ast = Jinter.parseScript(player_js, { ecmaVersion: 'latest', ranges: true });

        sig_timestamp = Player.extractSigTimestamp(player_js);
        const global_variable = Player.extractGlobalVariable(player_js, ast);
        sig_sc = Player.extractSigSourceCode(player_js, global_variable);
        nsig_sc = Player.extractNSigSourceCode(player_js, ast, global_variable);

        write("Deciphering Scripts...");
        write("Deciphered Scripts");
        resolve("done");
    });
}

function decipherUrl(url) {
    const args = new URLSearchParams(url);
    const url_components = new URL(args.get('url') || url);

    if (args.get('s') != null) {
        const signature = Utils.Platform.shim.eval(sig_sc, {
            sig: args.get('s')
        });
        const sp = args.get('sp');
        if (sp) {
            url_components.searchParams.set(sp, signature);
        } else {
            url_components.searchParams.set('signature', signature);
        }
    }

    const n = url_components.searchParams.get('n');
    if (n != null) {
        var nsig = Utils.Platform.shim.eval(nsig_sc, {
            nsig: n
        });
        url_components.searchParams.set('n', nsig);
    }

    url_components.searchParams.set('pot', poToken);
    url_components.searchParams.set('cver', cver);
    return url_components.toString();
}

async function mergeAudioVideo(videoUrl, audioUrl, title, format) {
    write("Merging audio and video streams...");
    
    try {
        await loadFFmpeg();
        
        // Fetch video and audio streams
        const videoResponse = await fetch(videoUrl);
        const audioResponse = await fetch(audioUrl);
        
        const videoBuffer = await videoResponse.arrayBuffer();
        const audioBuffer = await audioResponse.arrayBuffer();
        
        // Write files to FFmpeg
        ffmpeg.FS('writeFile', 'video.mp4', new Uint8Array(videoBuffer));
        ffmpeg.FS('writeFile', 'audio.mp4', new Uint8Array(audioBuffer));
        
        // Run FFmpeg command to merge
        await ffmpeg.run(
            '-i', 'video.mp4', 
            '-i', 'audio.mp4',
            '-c', 'copy',
            'output.mp4'
        );
        
        // Read the output file
        const data = ffmpeg.FS('readFile', 'output.mp4');
        
        // Create download link
        const blob = new Blob([data.buffer], { type: 'video/mp4' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `${title}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        // Clean up
        URL.revokeObjectURL(url);
        ffmpeg.FS('unlink', 'video.mp4');
        ffmpeg.FS('unlink', 'audio.mp4');
        ffmpeg.FS('unlink', 'output.mp4');
        
        write("Download complete!");
    } catch (error) {
        console.error('Error merging streams:', error);
        write("Error merging streams: " + error.message);
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function getBestAudioStream(adaptiveFormats) {
    let bestAudio = null;
    let highestBitrate = 0;
    
    for (const format of adaptiveFormats) {
        if (format.mimeType && format.mimeType.includes('audio')) {
            const bitrate = format.bitrate || 0;
            if (bitrate > highestBitrate) {
                highestBitrate = bitrate;
                bestAudio = format;
            }
        }
    }
    
    return bestAudio;
}

async function handleDownloadWithAudio(videoFormat, adaptiveFormats, title) {
    const audioFormat = await getBestAudioStream(adaptiveFormats);
    
    if (!audioFormat) {
        write("No audio stream found");
        return;
    }
    
    const videoUrl = decipherUrl(videoFormat.url);
    const audioUrl = decipherUrl(audioFormat.url);
    
    await mergeAudioVideo(videoUrl, audioUrl, title, 'mp4');
}

window.getDownloadStreams = async () => {
    write("Getting Deciphers...");
    await getDeciphers();
    write("Fetching Video Info...");

    var id = "";
    if (window.location.pathname.indexOf("shorts") > -1) {
        id = window.location.pathname.substr(8, window.location.pathname.length);
    } else {
        id = new URLSearchParams(window.location.search).get("v");
    }

    var body = {
        "videoId": id,
        "racyCheckOk": true,
        "contentCheckOk": true,
        "playbackContext": {
            "contentPlaybackContext": {
                "vis": 0,
                "splay": false,
                "lactMilliseconds": "-1",
                "signatureTimestamp": sig_timestamp
            }
        },
        "serviceIntegrityDimensions": {
            "poToken": poToken
        },
        "context": {
            "client": {
                "hl": "en",
                "gl": "US",
                "remoteHost": "",
                "screenDensityFloat": 1,
                "screenHeightPoints": 1440,
                "screenPixelDensity": 1,
                "screenWidthPoints": 2560,
                "visitorData": visitorData,
                "clientName": "ANDROID",
                "clientVersion": cver,
                "osName": "Android",
                "osVersion": "12",
                "userAgent": "com.google.android.youtube/19.35.36(Linux; U; Android 13; en_US; SM-S908E Build/TP1A.220624.014) gzip",
                "platform": "DESKTOP",
                "clientFormFactor": "UNKNOWN_FORM_FACTOR",
                "userInterfaceTheme": "USER_INTERFACE_THEME_LIGHT",
                "timeZone": "Asia/Calcutta",
                "originalUrl": "https://www.youtube.com",
                "deviceMake": "",
                "deviceModel": "",
                "browserName": "Chrome",
                "browserVersion": "125.0.0.0",
                "utcOffsetMinutes": 330,
                "memoryTotalKbytes": "8000000",
                "mainAppWebInfo": {
                    "graftUrl": "https://www.youtube.com",
                    "pwaInstallabilityStatus": "PWA_INSTALLABILITY_STATUS_UNKNOWN",
                    "webDisplayMode": "WEB_DISPLAY_MODE_BROWSER",
                    "isWebNativeShareAvailable": true
                }
            },
            "user": {
                "enableSafetyMode": false,
                "lockedSafetyMode": false
            },
            "request": {
                "useSsl": true,
                "internalExperimentFlags": []
            }
        }
    };

    var info = await fetch("https://m.youtube.com/youtubei/v1/player?prettyPrint=false", {
        method: "POST",
        body: JSON.stringify(body)
    }).then((res) => res.json());

    handleDownloadStreams(info);
};

function handleDownloadStreams(info) {
    console.log(info?.streamingData);

    var ytproDownDiv = document.getElementById("downytprodiv");
    var thumb = info?.videoDetails?.thumbnail?.thumbnails;
    var vids = info?.streamingData?.formats;
    var avids = info?.streamingData?.adaptiveFormats;
    var cap = info?.captions?.playerCaptionsTracklistRenderer?.captionTracks;
    var t = info?.videoDetails?.title.replace(/[|\\?*<:"'>]/g, "");

    ytproDownDiv.innerHTML = `<style>
        #downytprodiv a{text-decoration:none;} 
        #downytprodiv li{list-style:none; display:flex;align-items:center;justify-content:center;border-radius:25px;padding:8px;margin:5px;margin-top:8px; cursor: pointer;}
        .download-btn { background: #007bff; color: white; padding: 10px 15px; border-radius: 5px; }
    </style>`;

    ytproDownDiv.innerHTML += "<h3>Video with Audio</h3><ul id='listurl'>";

    // Add combined video+audio options
    for (var x in vids) {
        if (vids[x].url) {
            ytproDownDiv.innerHTML += `<li class="download-btn" onclick="handleDownloadWithAudio(${JSON.stringify(vids[x])}, ${JSON.stringify(avids)}, '${t}')">
                ${vids[x].qualityLabel} ${formatFileSize(((vids[x].bitrate * (vids[x].approxDurationMs / 1000)) / 8))}
            </li>`;
        }
    }

    ytproDownDiv.innerHTML += "<h3>Audio Only</h3>";
    for (var x in avids) {
        if (avids[x].mimeType && avids[x].mimeType.includes("audio")) {
            var url = avids[x].url;
            ytproDownDiv.innerHTML += `<li class="download-btn" onclick="YTDownVid('${decipherUrl(url)}', '${t}', 'mp3')">
                Audio ${avids[x]?.audioTrack?.displayName || ""} | ${avids[x].audioQuality.replace("AUDIO_QUALITY_", "")} ${formatFileSize(avids[x].contentLength)}
            </li>`;
        }
    }

    // Add thumbnail download options
    ytproDownDiv.innerHTML += "<h3>Thumbnails</h3>";
    for (var x in thumb) {
        ytproDownDiv.innerHTML += `<li class="download-btn" onclick="YTDownVid('${thumb[x].url}', '${t + Date.now()}', 'png')">
            <img src="${thumb[x].url}" style="height: 50px; margin-right: 10px;"> ${thumb[x].height} × ${thumb[x].width}
        </li>`;
    }

    // Add captions download options
    if (cap && cap.length) {
        ytproDownDiv.innerHTML += "<h3>Captions</h3>";
        for (var x in cap) {
            const baseUrl = cap[x].baseUrl.replace("&fmt=srv3", "");
            ytproDownDiv.innerHTML += `
                <div>
                    <span>${cap[x]?.name?.runs[0]?.text}</span>
                    <button class="download-btn" onclick="downCap('${baseUrl}&fmt=sbv', '${t}.txt')">TXT</button>
                    <button class="download-btn" onclick="downCap('${baseUrl}&fmt=srt', '${t}.srt')">SRT</button>
                    <button class="download-btn" onclick="downCap('${baseUrl}', '${t}.xml')">XML</button>
                    <button class="download-btn" onclick="downCap('${baseUrl}&fmt=vtt', '${t}.vtt')">VTT</button>
                </div>
            `;
        }
    }
}

// Helper function to download files
function YTDownVid(url, title, format) {
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// Helper function to download captions
function downCap(url, filename) {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// Initialize FFmpeg when the script loads
loadFFmpeg().then(() => {
    console.log("FFmpeg loaded successfully");
}).catch(err => {
    console.error("Failed to load FFmpeg:", err);
});
