/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/** \file DbSelectionPanel.cpp
* 
*/

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#ifdef __WXMSW__
#include <wx/msw/msvcrt.h>
#endif

#include <wx/filename.h>
#include <wx/filedlg.h>

#include "core/PWScore.h"
#include "os/transport.h"

#include "DbSelectionPanel.h"
#include "SafeCombinationCtrl.h"
#include "wxUtilities.h"

#ifndef NO_YUBI
#include "graphics/Yubikey-button.xpm"

#define ID_YUBIBTN 10001
#define ID_YUBISTATUS 10002
#endif

DbSelectionPanel::DbSelectionPanel(wxWindow* parent,
                                    const wxString& filePrompt,
                                    const wxString& filePickerCtrlTitle,
                                    bool autoValidate,
                                    PWScore* core,
                                    unsigned rowsep,
                                    int buttonConfirmationId,
                                    const wxString filename) : wxPanel(parent),
                                                                m_locationCtrl(nullptr),
                                                                m_sc(nullptr),
                                                                m_bAutoValidate(autoValidate),
                                                                m_core(core),
                                                                m_confirmationButtonId(buttonConfirmationId),
                                                                m_browseTitle(filePickerCtrlTitle)
{
  wxSizerFlags borderFlags = wxSizerFlags().Border(wxLEFT|wxRIGHT, SideMargin);

  /* This doesn't work since the second Border() call overwrites all the
   * previous border values.  So now we have to insert separators by hand
   */
  //wxSizerFlags rowFlags = borderFlags.Border(wxBOTTOM, RowSeparation);

  wxBoxSizer* panelSizer = new wxBoxSizer(wxVERTICAL);
  panelSizer->AddSpacer(TopMargin);

  panelSizer->Add(new wxStaticText(this, wxID_ANY, filePrompt), borderFlags);
  panelSizer->AddSpacer(RowSeparation);
  m_filepath = filename;

  /* Location row: combo box (accepts both local paths and transport URLs)
   * plus a Browse button for local-file selection. */
  m_locationCtrl = new wxComboBox(this, wxID_ANY, filename,
                                  wxDefaultPosition, wxDefaultSize,
                                  0, nullptr, wxCB_DROPDOWN);
  auto *browseBtn = new wxButton(this, wxID_ANY, _("Browse..."));
  Bind(wxEVT_BUTTON, &DbSelectionPanel::OnBrowseClicked, this, browseBtn->GetId());

  auto *locationRow = new wxBoxSizer(wxHORIZONTAL);
  locationRow->Add(m_locationCtrl, 1, wxEXPAND | wxALL, 0);
  locationRow->Add(browseBtn, 0, wxLEFT | wxALIGN_CENTER_VERTICAL, 5);
  panelSizer->Add(locationRow, borderFlags.Expand());
  panelSizer->AddSpacer(RowSeparation*rowsep);

  panelSizer->Add(new wxStaticText(this, wxID_ANY, _("Master Password:")), borderFlags);
  panelSizer->AddSpacer(RowSeparation);
  
  m_sc = new SafeCombinationCtrl(this);
  m_sc->SetValidatorTarget(&m_combination);

  auto horizontalSizer = new wxBoxSizer(wxHORIZONTAL);
  horizontalSizer->Add(m_sc, 1, wxALL|wxEXPAND, 0);

#ifndef NO_YUBI
  auto yubiBtn = new wxBitmapButton(this , ID_YUBIBTN, wxBitmap(Yubikey_button_xpm),
    wxDefaultPosition, ConvertDialogToPixels(wxSize(40, 12)), wxBU_AUTODRAW );
  horizontalSizer->Add(yubiBtn, 0, wxALIGN_CENTER|wxLEFT|wxSHAPED, 5);
  Bind(wxEVT_BUTTON, &DbSelectionPanel::OnYubibtnClick, this);
#endif

  panelSizer->Add(horizontalSizer, borderFlags.Expand());
  panelSizer->AddSpacer(5);

#ifndef NO_YUBI
  auto yubiStatusCtrl = new wxStaticText(this, ID_YUBISTATUS, _("Insert YubiKey"),
    wxDefaultPosition, wxDefaultSize, 0 );
  panelSizer->Add(yubiStatusCtrl, borderFlags.Expand());
#endif

  SetSizerAndFit(panelSizer);

#ifndef NO_YUBI
  SetupMixin(this, FindWindow(ID_YUBIBTN), FindWindow(ID_YUBISTATUS));
  Bind(wxEVT_TIMER, &DbSelectionPanel::OnPollingTimer, this);
#endif
  
  //The parent window must call our TransferDataToWindow and TransferDataFromWindow
  m_parent->SetExtraStyle(m_parent->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY);
}

void DbSelectionPanel::SelectCombinationText()
{
  m_sc->SelectCombinationText();
}

bool DbSelectionPanel::DoValidation()
{
  //the data has not been transferred from the window to our members yet, so get them from the controls
  if (wxWindow::Validate()) {

    wxString path = m_locationCtrl->GetValue();

    if (path.IsEmpty()) {
      wxMessageBox(_("You must specify a file or URL."), _("Error"), wxOK | wxICON_EXCLAMATION, this);
      return false;
    }

    std::string path_utf8(path.mb_str(wxConvUTF8));

    if (pws_is_transport_url(path_utf8)) {
      /* URL path: verify that a transport plugin exists for the scheme */
      const PWSTransport *t = pws_find_transport(path_utf8);
      if (!t) {
        wxString scheme = path.BeforeFirst(':');
        wxMessageBox(
          wxString::Format(_("No transport plugin found for scheme '%s'.\nCannot open '%s'."),
                           scheme, path),
          _("Transport plugin not found"), wxOK | wxICON_ERROR, this);
        return false;
      }
      /* For URL paths the same-file check compares strings directly */
      if (path_utf8 == std::string(towxstring(m_core->GetCurFile()).mb_str(wxConvUTF8))) {
        wxMessageBox(_("That database is already open."), _("Error"), wxOK | wxICON_WARNING, this);
        return false;
      }
    } else {
      /* Local file path */
      wxFileName wxfn(path);

      //Did the user enter a valid file path
      if (!wxfn.FileExists()) {
        wxMessageBox(_("File or path not found."), _("Error"), wxOK | wxICON_EXCLAMATION, this);
        return false;
      }

      //Did he enter the same file that's currently open?
      if (wxfn.SameAs(wxFileName(towxstring(m_core->GetCurFile())))) {
        // It is the same damn file
        wxMessageBox(_("That file is already open."), _("Error"), wxOK | wxICON_WARNING, this);
        return false;
      }
    }

    m_combination = m_yubiCombination.empty() ? m_sc->GetCombination() : m_yubiCombination;
    //Does the combination match?  CheckPasskey calls pws_os::FOpen which handles transport URLs.
    if (m_core->CheckPasskey(tostringx(path), m_combination) != PWScore::SUCCESS) {
      wxString errmess(_("Incorrect master password, not a Password Safe database,\nor a corrupt database."));
      wxMessageBox(errmess, _("Can't open a password database"), wxOK | wxICON_ERROR, this);
      SelectCombinationText();
      m_combination.clear();
      return false;
    }

    m_filepath = path;
    return true;
  }
  else {
    return false;
  }
}

bool DbSelectionPanel::TransferDataFromWindow()
{
  // We need to override this way because putting the Yubikey-derived passphrase in the m_sc control
  // would potentially expose it to users.
  bool retval = wxPanel::TransferDataFromWindow();
  if (!m_yubiCombination.empty()) {
    m_combination = m_yubiCombination;
  }
  return retval;
}


void DbSelectionPanel::OnBrowseClicked(wxCommandEvent& WXUNUSED(event))
{
  wxString curVal = m_locationCtrl->GetValue();

  wxFileDialog dlg(this, m_browseTitle, wxEmptyString, wxEmptyString,
                   _("Password Safe Databases (*.psafe4; *.psafe3; *.dat)|*.psafe4;*.psafe3;*.dat"
                     "|Password Safe Backups (*.bak)|*.bak"
                     "|Password Safe Intermediate Backups (*.ibak)|*.ibak"
                     "|All files (*.*; *)|*.*;*"),
                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);

  /* Pre-navigate to the current file's directory if it is a local path */
  if (!curVal.IsEmpty() &&
      !pws_is_transport_url(std::string(curVal.mb_str(wxConvUTF8)))) {
    wxFileName fn(curVal);
    if (fn.DirExists())
      dlg.SetDirectory(fn.GetPath());
  }

  if (dlg.ShowModal() == wxID_OK) {
    m_locationCtrl->SetValue(dlg.GetPath());
    m_sc->SelectCombinationText();
  }
}

#ifndef NO_YUBI
/*!
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_YUBIBTN
 */

void DbSelectionPanel::OnYubibtnClick(wxCommandEvent& WXUNUSED(event))
{
  m_sc->AllowEmptyCombinationOnce();  // Allow blank password when Yubi's used

  if (TransferDataFromWindow()) { // don't Validate(), as password won't be right. (BR877)
    StringX response;
    bool oldYubiChallenge = ::wxGetKeyState(WXK_SHIFT); // for pre-0.94 databases
    if (PerformChallengeResponse(this, m_combination, response, oldYubiChallenge)) {
      m_yubiCombination = m_combination = response;
      GetParent()->GetEventHandler()->AddPendingEvent(wxCommandEvent(wxEVT_BUTTON, m_confirmationButtonId));
      return;
    }
  }
}

void DbSelectionPanel::OnPollingTimer(wxTimerEvent& event)
{
  if (event.GetId() == POLLING_TIMER_ID) {
    HandlePollingTimer(); // in YubiMixin
  }
}
#endif
