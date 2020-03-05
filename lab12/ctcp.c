/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"
#include <string.h>
#include <unistd.h>

#define WAITING_INPUT       0x100
#define WAITING_ACK         0x200
#define FIN_WAIT_1          0x400
#define FIN_WAIT_2          0x800
#define TIME_WAIT           0x010
#define CLOSE_WAIT          0x020
#define LAST_ACK            0x040
#define WAITING_FLUSH       0x080
#define CLOSED              0x001
#define ZEROS               0x000
/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  linked_list_t *segments;  /* Linked list of segments sent to this connection.
                               It may be useful to have multiple linked lists
                               for unacknowledged segments, segments that
                               haven't been sent, etc. Lab 1 uses the
                               stop-and-wait protocol and therefore does not
                               necessarily need a linked list. You may remove
                               this if this is the case for you */

  /* FIXME: Add other needed fields. */
    uint32_t seqno; // seqno+ byte len (sender)= ackno (receiver)
    uint32_t ackno;
    uint32_t numSentByte;  
    uint32_t numRecvByte;  
    uint32_t numFlushedBytes;
    uint8_t sent_buffer[MAX_SEG_DATA_SIZE];  // buffer just sent
    uint8_t recv_buffer[MAX_SEG_DATA_SIZE];   //buffer //just received
    uint32_t timeout;
    uint16_t recv_window;     // recv window size
    uint16_t sent_window;     // send window size
    uint32_t retransmitCount;
    struct timeval lastTransmissionTime;
    uint16_t status;
};
int is_segment_corrupted(ctcp_segment_t *segment,size_t received_length); //checksum
void create_segment_and_send(ctcp_state_t *state,char *buffer, uint16_t buffer_len, uint32_t flags);
void process_data_segment(ctcp_state_t *state,ctcp_segment_t *segment);
void process_ack_segment(ctcp_state_t *state,ctcp_segment_t *segment);
void process_fin_segment(ctcp_state_t *state,ctcp_segment_t *segment);
int handle_retransmission(ctcp_state_t *state);
/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */


ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */
  state->seqno = 1;
  state->ackno = 1;
  state->numSentByte = 0;
  state->numRecvByte = 0;
  state->numFlushedBytes = 0;
  state->status = WAITING_INPUT;
  state->timeout = cfg->rt_timeout;
  state->recv_window = cfg->recv_window;
  state->sent_window = cfg->send_window;
  state->retransmitCount = 0;
  memset(state->sent_buffer, 0, MAX_SEG_DATA_SIZE);
  memset(state->recv_buffer, 0, MAX_SEG_DATA_SIZE);
  state->segments = ll_create();
  free(cfg);  
  return state;
  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */

  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  /* FIXME */
  if (state->status & WAITING_INPUT)
  {
    int bytesLeft = state->sent_window - state->numSentByte;
    int max_byte=bytesLeft < MAX_SEG_DATA_SIZE ? bytesLeft : MAX_SEG_DATA_SIZE;
    int byte_read=conn_input(state->conn,(char*)state->sent_buffer,max_byte);
    /* If no input */
    if (byte_read==0)
      return;
    /* If read EOF */
    else if (byte_read==-1)
    {
      state->status &= ~WAITING_INPUT;
      state->status |= FIN_WAIT_1;
      state->numSentByte=0;
      create_segment_and_send(state,NULL,0,FIN);
    }
    else 
    {
      fprintf(stdout, "send data\n" );
      create_segment_and_send(state,(char *)state->sent_buffer,byte_read,ACK);
      state->numSentByte+=byte_read;
      state->seqno+=byte_read;
      if(state->numSentByte==state->sent_window)
      {
        state->status &= ~WAITING_INPUT;
        state->numSentByte=0;
      }
      state->status |= WAITING_ACK;
    }
  }
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  /* FIXME */
  if(is_segment_corrupted(segment, len)){
    free(segment);
    return;
  }
  uint32_t flags = segment->flags;
  /* Received data segment */
  if (ntohs(segment->len) > sizeof(ctcp_segment_t)) {
      process_data_segment(state, segment);
      if (flags & TH_ACK)
          process_ack_segment(state, segment);
  }
  else {
      if (flags & TH_ACK)
          process_ack_segment(state, segment);
      else if (flags & TH_FIN) 
          process_fin_segment(state, segment);
  }
  free(segment);

  //state CLOSED 
  // if (state->status & TIME_WAIT || state->status ) {
  //     ctcp_destroy(state);
  // }

  return;
}

void ctcp_output(ctcp_state_t *state) {
  /* FIXME */
    size_t bufferSpace = conn_bufspace(state->conn);

    if (bufferSpace == 0) {
        state->status |= WAITING_FLUSH;
        return;
    }

    size_t bytesLeft = state->numRecvByte - state->numFlushedBytes; /* how many bytes we still have to flush */
    size_t writeLength = (bytesLeft < bufferSpace) ? bytesLeft : bufferSpace;
    char *data = (char *)state->recv_buffer;
    uint16_t offset = state->numFlushedBytes;

    int bytesWritten = conn_output(state->conn, &data[offset], writeLength);

    state->numFlushedBytes += bytesWritten;

    if(state->numFlushedBytes == state->numRecvByte) {
        state->status &= ~WAITING_FLUSH;
        state->numFlushedBytes = 0;
    }
    return;
}

void ctcp_timer() {
  /* FIXME */
    ctcp_state_t *state = state_list;

    //go through every open reliable connection and retransmit packets as needed  
    while(state)
    {
        if (handle_retransmission(state) == 0)
            state = state->next;
    }
}
int is_segment_corrupted(ctcp_segment_t *segment,size_t received_length)
{
  int segmentLength = (int) ntohs (segment->len);

    /* If we received fewer bytes than the segment's size declare corruption. */
  if (received_length < (size_t)segmentLength) 
      return 1;

  uint16_t segmentChecksum = segment->cksum;
  memset (&(segment->cksum), 0, sizeof(segment->cksum));
  uint16_t computedChecksum = cksum(segment, segmentLength);

  return segmentChecksum != computedChecksum;
}
void create_segment_and_send(ctcp_state_t *state,char *buffer, uint16_t buffer_len, uint32_t flags)
{
  ctcp_segment_t *smt;
  uint16_t segment_len;
  segment_len = buffer_len+sizeof(ctcp_segment_t);
  smt=calloc(segment_len,1);
  smt->len=htons(segment_len);
  smt->seqno=htonl(state->seqno);
  smt->ackno=htonl(state->ackno);
  smt->window=htons(state->sent_window); 
  smt->flags=htonl(flags);
  smt->cksum=0;
  //fprintf(stdout, "%d\n",smt->len);
  if(buffer_len>0)
  {
    memcpy(smt->data,buffer,buffer_len);
    ll_add(state->segments,smt);
  }
  if(flags & FIN)
  {
    ll_add(state->segments,smt);
  }
  smt->cksum=cksum(smt,segment_len);
  conn_send(state->conn,smt, segment_len);
  print_hdr_ctcp(smt);
  return ;
}
void process_data_segment(ctcp_state_t *state, ctcp_segment_t *segment)
{
  //check whether ackno of the segment correct
  print_hdr_ctcp(segment);
  uint16_t seq_len=ntohs(segment->len);
  uint32_t seqno=ntohl(segment->seqno);
  if (seqno<state->ackno)  //unwanted segment
  {
    create_segment_and_send(state,NULL,0,ACK); //resend ACK
    fprintf(stdout, "send back ack ,not wanted\n" );
    return;
  }
  if(seqno==state->ackno)
  {
    state->status |= WAITING_FLUSH;
    state->numRecvByte=seq_len-sizeof(ctcp_segment_t);
    state->ackno=seqno+state->numRecvByte;
    fprintf(stdout, "%d\n",state->ackno);
    memcpy(state->recv_buffer,segment->data,state->numRecvByte);
    fprintf(stdout, "send back ack \n" );
    create_segment_and_send(state,NULL,0,ACK);
    ctcp_output(state);
    //conn_output(state->conn,(char *)state->recv_buffer,state->numRecvByte);
  }
}
void process_ack_segment(ctcp_state_t *state,ctcp_segment_t *segment)
{
  if(state->status & WAITING_ACK)
  {
    //we use stop and wait so the head of the list is the current segment
    ll_remove(state->segments,state->segments->head);
    state->status &=~WAITING_ACK;
    state->status |= WAITING_INPUT;
    return;
  }
  if(state->status & FIN_WAIT_1)
  {
    state->status &= ~FIN_WAIT_1;
    state->status |= FIN_WAIT_2;
  }
  if(state->status & LAST_ACK)
  {
    state->status &= ~LAST_ACK;
    state->status |= CLOSED;
  }
  print_hdr_ctcp(segment);
  return;
}
void process_fin_segment( ctcp_state_t *state , ctcp_segment_t *segment)
{
  //passive close
  if(state->status & WAITING_INPUT)
  {
    state->status &= ~WAITING_INPUT;
    state->status |= CLOSE_WAIT;
    create_segment_and_send(state,NULL,0,ACK);
    sleep(1);
    create_segment_and_send(state,NULL,0,FIN);
    state->status &= ~CLOSE_WAIT;
    state->status |= LAST_ACK; 
    return;
  }
  if(state->status & FIN_WAIT_2)
  {
    state->status &= ~FIN_WAIT_2;
    state->status |= TIME_WAIT;
    create_segment_and_send(state,NULL,0,ACK);
    sleep(1);
    ctcp_destroy(state);
  }
}
int get_time_since_last_transmission (ctcp_state_t *state) {

    struct timeval now;
    gettimeofday (&now, NULL);  
    return ( ( (int)now.tv_sec * 1000 + (int)now.tv_usec / 1000 ) - 
    ( (int)state->lastTransmissionTime.tv_sec * 1000 + (int)state->lastTransmissionTime.tv_usec / 1000 ) );
}

int handle_retransmission (ctcp_state_t *state)
{

    /* Retransmit over 5 times, terminate connect */    
    if (state->retransmitCount > 5) {
        ctcp_destroy(state);
        return 0;
    }

    // /* Only retransmit if we are waiting for acks */
    if (state->status & WAITING_ACK) {
        int millisecondsSinceTransmission = get_time_since_last_transmission(state);
        linked_list_t *list = state->segments;
        
        /* last transmission timed out, retransmit last packet */
        if (millisecondsSinceTransmission > state->timeout) {
            
            if (state->status & FIN_WAIT_1)
                create_segment_and_send(state, NULL, 0, FIN);
            else if (list->head != NULL) {
                ctcp_segment_t *segment = (ctcp_segment_t *) list->head->object;
                conn_send(state->conn, segment, ntohs(segment->len));
            }
            else
                return state->retransmitCount;

            gettimeofday(&(state->lastTransmissionTime), NULL); /* record retransmission time */
            state->retransmitCount++;
            return state->retransmitCount;
        }

     }
    
    else if (state->status & WAITING_INPUT)
        state->retransmitCount = 0;

     return 0;
}