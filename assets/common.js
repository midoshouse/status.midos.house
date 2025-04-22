const stateText = document.getElementById('websocket-state');

function startWebsocket() {
    try {
        stateText.textContent = 'Connecting for automatic status updates…';
        const sock = new WebSocket("wss://status.midos.house/websocket");
        sock.onopen = () => {
            stateText.textContent = 'Status is updating live.';
        };
        sock.onmessage = (event) => {
            const payload = JSON.parse(event.data);
            switch (payload.type) {
                case 'change': {
                    if ('running' in payload) {
                        const mhCurrent = document.createElement('a');
                        mhCurrent.setAttribute('href', `https://github.com/midoshouse/midos.house/commit/${payload.running}`);
                        mhCurrent.appendChild(document.createTextNode(payload.running.slice(0, 7)));
                        document.getElementById('mh-current').replaceChildren(mhCurrent);
                    }
                    if ('future' in payload) {
                        if (payload.future.length == 0) {
                            document.getElementById('mh-future-empty').removeAttribute('style');
                            document.getElementById('mh-future-nonempty').setAttribute('style', 'display: none;');
                        } else {
                            document.getElementById('mh-future-empty').setAttribute('style', 'display: none;');
                            document.getElementById('mh-future-nonempty').removeAttribute('style');
                            const futureChildren = payload.future
                                .map((commit) => {
                                    const row = document.createElement('tr');
                                    const hashCell = document.createElement('td');
                                    const hash = document.createElement('a');
                                    hash.setAttribute('href', `https://github.com/midoshouse/midos.house/commit/${commit.commitHash}`);
                                    hash.appendChild(document.createTextNode(commit.commitHash.slice(0, 7)));
                                    hashCell.appendChild(hash);
                                    row.appendChild(hashCell);
                                    const msgCell = document.createElement('td');
                                    msgCell.appendChild(document.createTextNode(commit.commitMsg));
                                    row.appendChild(msgCell);
                                    const statusCell = document.createElement('td');
                                    switch (commit.status.type) {
                                        case 'pending': statusCell.appendChild(document.createTextNode('waiting for other builds to finish')); break;
                                        case 'skipped': statusCell.appendChild(document.createTextNode('skipped')); break;
                                        case 'build': statusCell.appendChild(document.createTextNode('building')); break;
                                        case 'prepareStopInit': statusCell.appendChild(document.createTextNode('waiting for reply to shutdown request')); break;
                                        case 'prepareStopAcquiringMutex': statusCell.appendChild(document.createTextNode('waiting for access to clean shutdown state')); break;
                                        case 'waitingForRooms': {
                                            const faviconContainer = document.createElement('div');
                                            faviconContainer.setAttribute('class', 'favicon-container');
                                            if (commit.status.rooms.length == 0) {
                                                faviconContainer.appendChild(document.createTextNode('(private async parts)'));
                                            } else {
                                                for (const room of commit.status.rooms) {
                                                    const roomLink = document.createElement('a');
                                                    roomLink.setAttribute('class', 'favicon');
                                                    roomLink.setAttribute('title', 'race room');
                                                    roomLink.setAttribute('href', `https://racetime.gg${room.roomUrl}`);
                                                    const favicon = document.createElement('img');
                                                    favicon.setAttribute('class', 'favicon');
                                                    favicon.setAttribute('alt', 'external link (racetime.gg)');
                                                    favicon.setAttribute('src', '/racetime.svg');
                                                    roomLink.appendChild(favicon);
                                                    faviconContainer.appendChild(roomLink);
                                                }
                                            }
                                            statusCell.appendChild(faviconContainer);
                                            break;
                                        }
                                        case 'deploy': statusCell.appendChild(document.createTextNode('deploying')); break;
                                    }
                                    row.appendChild(statusCell);
                                    return row;
                                });
                            document.getElementById('mh-future-tbody').replaceChildren(...futureChildren);
                        }
                    }
                    if ('selfFuture' in payload) {
                        if (payload.selfFuture.length == 0) {
                            document.getElementById('self-future-empty').removeAttribute('style');
                            document.getElementById('self-future-nonempty').setAttribute('style', 'display: none;');
                        } else {
                            document.getElementById('self-future-empty').setAttribute('style', 'display: none;');
                            document.getElementById('self-future-nonempty').removeAttribute('style');
                            const selfFutureChildren = payload.selfFuture
                                .map((commit) => {
                                    const row = document.createElement('tr');
                                    const hashCell = document.createElement('td');
                                    const hash = document.createElement('a');
                                    hash.setAttribute('href', `https://github.com/midoshouse/status.midos.house/commit/${commit.commitHash}`);
                                    hash.appendChild(document.createTextNode(commit.commitHash.slice(0, 7)));
                                    hashCell.appendChild(hash);
                                    row.appendChild(hashCell);
                                    const msgCell = document.createElement('td');
                                    msgCell.appendChild(document.createTextNode(commit.commitMsg));
                                    row.appendChild(msgCell);
                                    const statusCell = document.createElement('td');
                                    switch (commit.status.type) {
                                        case 'pending': statusCell.appendChild(document.createTextNode('waiting for other builds to finish')); break;
                                        case 'skipped': statusCell.appendChild(document.createTextNode('skipped')); break;
                                        case 'build': statusCell.appendChild(document.createTextNode('building')); break;
                                    }
                                    row.appendChild(statusCell);
                                    return row;
                                });
                            document.getElementById('self-future-tbody').replaceChildren(...selfFutureChildren);
                        }
                    }
                    break;
                }
                case 'refresh': {
                    // mhstatus is about to restart to update, schedule a reload
                    document.getElementById('self-future-empty').removeAttribute('style');
                    document.getElementById('self-future-empty').replaceChildren(document.createTextNode('status.midos.house is restarting…'));
                    document.getElementById('self-future-nonempty').setAttribute('style', 'display: none;');
                    setTimeout(window.location.reload.bind(window.location), 1000);
                    break;
                }
            }
        };
        sock.onerror = (event) => {
            throw event;
        }
        sock.onclose = () => {
            stateText.textContent = 'Connection for automatic status updates lost, reconnecting…';
            setTimeout(startWebsocket, 1000);
        }
    } catch (e) {
        stateText.textContent = `Error checking for status updates: ${e}. Please report this error to Fenhl.`;
    }
}

startWebsocket();
