/*
 * Copyright (c) 2018 Ant Financial Services Group.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _TLE_GLUE_ZEROCOPY_H_
#define _TLE_GLUE_ZEROCOPY_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This API performs recv operation on specified socket, and it's
 * optimized for zero copy, which means the caller does not need to
 * prepare the buffer, instead, it will get a pointer on success.
 * @param sockfd
 *   the file descriptor for the socket.
 * @param buf
 *   after successfully receiving some payload, the pointer of the
 *   received buffer will be stored in *buf.
 * @return
 *   the number of bytes received, or -1 if an error occurred, or 0
 *   if a stream socket peer has performed an orderly shutdown.
 *
 */
ssize_t recv_zc(int sockfd, void **buf);

/**
 * This API performs send operation on specified socket, and it's
 * optimized for zero copy, which means the caller does not need to
 * free the buffer, not even touch that buffer even after calling this
 * API; the buffer will be freed after an ack from the socket peer.
 * @param sockfd
 *   the file descriptor for the socket.
 * @param buf
 *   The pointer to the payload buffer to be sent.
 * @param len
 *   The length of the payload buffer to be sent.
 * @return
 *   the number of bytes sent, or -1 if an error occurred.
 */
ssize_t send_zc(int sockfd, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /*_TLE_GLUE_ZEROCOPY_H_ */
