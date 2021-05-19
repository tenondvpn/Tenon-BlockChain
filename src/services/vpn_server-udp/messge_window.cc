#include "services/vpn_server/messge_window.h"


namespace tenon {

namespace vpn {

    uint32_t MessageWindow::all_sent_msg_count_ = 0;
    uint32_t MessageWindow::all_sent_start_msg_index_ = 0;
    uint32_t MessageWindow::all_recv_msg_count_ = 0;
    uint32_t MessageWindow::all_recv_start_msg_index_ = 0;
    uint32_t MessageWindow::all_sent_out_start_msg_index_ = 0;
    uint32_t MessageWindow::all_recv_from_start_msg_index_ = 0;

}  // namespace vpn 

}  // namespace tenon
