import styled from 'styled-components';
import { LaneHeader } from 'react-trello/dist/styles/Base';

export const Header = styled(LaneHeader)`
  color: ${(props) => props.theme.commonColors.white};
  width: 15.9375rem;
  padding: 0;
`;

export const Title = styled.div`
  font-size: ${(props) => props.theme.commonFontSizes.lg};
  overflow: hidden;
  text-overflow: ellipsis;
`;

export const Dot = styled.span`
  padding-left: 0.625rem;
  padding-right: 0.3125rem;
`;