
export const inspect = (...things) => things.forEach(thing => console.dir(thing, { depth: null, colors: true }));

export const inspectAxiosResponse = response => {
    inspect({
        request: {
            method: response.request.method,
            protocol: response.request.protocol,
            host: response.request.host,
            path: response.request.path,
            headers: response.request.getHeaders(),
        },
        response: {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
            data: response.data,
        }
    });
};

export const inspectAxiosError = error => {
    if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        inspectAxiosResponse(error.response);
    } else if (error.request) {
        // The request was made but no response was received
        // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
        // http.ClientRequest in node.js
        console.log(error.request);
    } else {
        // Something happened in setting up the request that triggered an Error
        console.log('Error', error.message);
    }
    console.log(error.config);
}
